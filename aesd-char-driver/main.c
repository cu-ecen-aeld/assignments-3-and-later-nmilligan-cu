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
#include "aesdchar.h"
#include "aesd-circular-buffer.h"
#include <linux/slab.h>

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Nicole Milligan"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

void aesd_trim(struct aesd_dev *dev)
{
	ssize_t index;
	struct aesd_buffer_entry *entry;
	AESD_CIRCULAR_BUFFER_FOREACH(entry,&dev->buffer,index) {
		kfree(entry->buffptr);
	}
}

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
		
	if(*f_pos >= rtnentry->size)
		goto out;
	if (*f_pos + count > rtnentry->size)
		count = rtnentry->size - *f_pos;
		
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
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
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
	aesd_trim(&aesd_device);
	mutex_destroy(&aesd_device.lock);
	
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
