## pvaldes 2017-01-27
## This script examines the content of each file recovered by photorec and will move it into a directory 
## with other files of the same type, making much easier to find what we are looking for. 

## i.e. All Phyton scripts in recup_dirXXX will be automatically moved to subdirectories in a new dir named Python/, 
## all makefiles to makefile/ all chunks of C++ files to C++/, etc... 

## 2017-02-04 name of the directories improved. Support for further classification inside each group.

for i in `find . -type f`; do
    classdir=`file $i | awk '{gsub("/" , "-"); gsub("," , ""); print $2}'`;
    typedir=`file $i | awk 'BEGIN {OFS="-";} {gsub("/" , "-"); gsub("," , ""); \
    if($6) print $2,$3,$4,$5,$6; \
    else if($5) print $2,$3,$4,$5; \
    else if($4) print $2,$3,$4; \
    else if($3) print $2,$3; \
    else print $2}'`;

## It the dir does not exist, create it in ../
    if [ ! -d "../$classdir" ]
     then
	 mkdir "../$classdir"
    fi
       
## If the names of dir class (parent) and type (subdir) are the same, do not create subdirs 
## and move files directly to the directory class
   if [ "$typedir" == "$classdir" ]
    then 
   	mv -i $i ../$classdir/
    fi
## Create subdirs and move all archives of its appropriate class and type.
   if [[ $typedir == "$classdir"* ]]
    then
	if [ ! -d "../$classdir/$typedir" ]
	then
	    mkdir "../$classdir/$typedir"
	fi
	mv -i $i ../$classdir/$typedir/
    fi
    
## reset variables
    typedir=""
    classdir=""
    
done

exit 0
