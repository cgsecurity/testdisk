## pvaldes 2017-01-27
## This script examine the content of each file recovered by photorec and will put it in a directory 
## with other files of the same type, making much easier to find what we are looking for. 
## It the dir does not exist will be created automatically in the current working directory.

## i.e. All Phyton scripts in recup_dirXXX will be automatically moved to subdirectories in a new dir named Python/, 
## all makefiles to makefile/ all chunks of C++ files to C++/, etc... 

## 2017-02-04 name of the directories improved. Support for further classification inside each group.

for i in `find . -type f`; do
    parentdir=`file $i | awk '{gsub("/" , "-"); gsub("," , ""); print $2}'`;
    typedir=`file $i | awk 'BEGIN {OFS="-";} {gsub("/" , "-"); gsub("," , ""); if($6) print $2,$3,$4,$5,$6; else if($5) print $2,$3,$4,$5; else if($4) print $2,$3,$4; else if($3) print $2,$3; else print $2}'`;

    if [ ! -d "../$parentdir" ]
     then
	 mkdir "../$parentdir"
       fi
       
   if [ "$typedir" == "$parentdir"]
   	mv -i $i ../$parentdir/
	fi

if [[ $typedir == "$parentdir"* ]]
    then
	if [ ! -d "../$parentdir/$typedir" ]
	then
	    mkdir "../$parentdir/$typedir"
	fi
	mv -i $i ../$parentdir/$typedir/
    fi
    typedir=""
    parentdir=""
    
done

exit 0
