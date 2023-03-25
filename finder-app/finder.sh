#!/bin/sh

filesdir=$1
searchstr=$2

if [ -z $filesdir ] || [ ! -d $filesdir ] || [ -z $searchstr ]
then
	echo 'Must supply a valid file directory and search string'
	exit 1
fi

file_count=$(ls -ApF $filesdir | grep -v @$ | wc -l)
search_count=$(grep -R $searchstr $filesdir | wc -l)
echo The number of files are "${file_count}" and the number of matching lines are "${search_count}";
