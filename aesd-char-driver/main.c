/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/slab.h>
#include "aesdchar.h"
#include "aesd-circular-buffer.h"
#include "aesd_ioctl.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Nicole Milligan"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    struct aesd_dev * dev;
    
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
	struct aesd_dev *dev = filp->private_data; 
    ssize_t retval = 0;
    size_t offset_rtn = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;
		
    
    struct aesd_buffer_entry *rtnentry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer,
                                                *f_pos,
                                                &offset_rtn);

    if(rtnentry == NULL || !rtnentry->buffptr || !&rtnentry->buffptr[offset_rtn])
		goto out;
		
	if (rtnentry->size - offset_rtn < count)
		count = rtnentry->size - offset_rtn;
		
	if( copy_to_user(buf, &rtnentry->buffptr[offset_rtn], count)){
		retval = -EFAULT;
		goto out;
	}
	*f_pos += count;
	retval = count;
	
    
    out:
		mutex_unlock(&dev->lock);
		return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    int i;
    struct aesd_dev *dev = filp->private_data;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;
	
	if(!dev->entry.buffptr){
		dev->entry.buffptr = kmalloc(count, GFP_KERNEL);
		
		if(!dev->entry.buffptr)
			goto out;
	}else{
		dev->entry.buffptr = krealloc(dev->entry.buffptr, dev->entry.size+count, GFP_KERNEL);
		
		if(!dev->entry.buffptr)
			goto out;
	}
	
	if( copy_from_user(&dev->entry.buffptr[dev->entry.size], buf, count)){
		retval = -EFAULT;
		goto out;
	}
	
	dev->entry.size = dev->entry.size + count;
	for(i = 0; i<dev->entry.size; i++){
		if (dev->entry.buffptr[i] == '\n'){
			aesd_circular_buffer_add_entry(&dev->buffer,&dev->entry);
			
			dev->entry.buffptr = NULL;
			dev->entry.size = 0;
		}
	}
	
	retval = count;
	
	out:
		mutex_unlock(&dev->lock);
		return retval;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int err = 0, index, newpos;
	int retval = 0;
	struct aesd_dev *dev = filp->private_data;
	struct aesd_seekto seek_to;
	
	if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) return -ENOTTY;
	
	switch(cmd){
		
		case AESDCHAR_IOCSEEKTO:
			PDEBUG("ioc");
			if( copy_from_user(&seek_to, (void __user *) arg, sizeof(struct aesd_seekto))){
				PDEBUG("copy failed");
				retval = -EINVAL;
				break;
			}
			
			if((dev->buffer.in_offs - dev->buffer.out_offs) < seek_to.write_cmd && !dev->buffer.full){
				PDEBUG("failed full and not enough values check");
				retval = -EINVAL;
				break;
			}
			
			struct aesd_buffer_entry entry;
			PDEBUG("about to enter loop");
			for(index=0; index <= seek_to.write_cmd; index++){
				entry = dev->buffer.entry[(dev->buffer.out_offs+index)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED];
				PDEBUG("index %lld with cmd %lld",index,seek_to.write_cmd);
				if (index < seek_to.write_cmd){
					newpos += entry.size;
				}
				else{
					if (entry.size < seek_to.write_cmd_offset){
						retval = -EINVAL;
						break;
					}
					newpos += seek_to.write_cmd_offset;
				}
				PDEBUG("end of loop newpos is %lld",newpos);
				
			}
			
			filp->f_pos = newpos;
			PDEBUG("final newpos is %lld",filp->f_pos);
	}
	
	return retval;
	
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
	struct aesd_dev *dev = filp->private_data;
	loff_t newpos;
	
	switch(whence){
		case 0: /*SEEK_SET */
			newpos = off;
			break;
			
		case 1: /*SEEK_CUR */
			newpos = filp->f_pos + off;
			break;
			
		case 2: /*SEEK_END */
			return -EINVAL;
			
		default: /* can't happen */
			return -EINVAL;
	}
	if (newpos < 0) return -EINVAL;
	filp->f_pos = newpos;
	return newpos;
}


struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
	
    /**
     * TODO: initialize the AESD specific portion of the device
     */
    aesd_circular_buffer_init(&aesd_device.buffer);
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
	uint8_t index = 0;
	struct aesd_buffer_entry *entry;
	AESD_CIRCULAR_BUFFER_FOREACH(entry,&aesd_device.buffer,index) {
		if(entry->buffptr!=NULL){	
			kfree(entry->buffptr);
		}
	}
	
	mutex_destroy(&aesd_device.lock);
	
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
