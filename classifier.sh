## pvaldes 2017-01-27
## This script examine the content of each file recovered by photorec and will put it in a directory 
## with other files of the same type, making much easier to find what we are looking for. 
## It the dir does not exist will be created automatically in the current working directory.

## i.e. All Phyton scripts in recup_dirXXX will be automatically moved to a new dir named Python-script/, 
## all makefiles to makefile/ all chunks of C++ files to C++-source-ascii-text, etc... 

## 2017-02-04 name of the directories improved. Maybe too much verbose now?

for i in `find . -type f`; do
     typedir=`file $i | awk 'BEGIN {OFS="-";} {gsub("/" , "-"); gsub("," , ""); if($6) print $2,$3,$4,$5,$6; else if($5) print $2,$3,$4,$5; else if($4) print $2,$3,$4; else if($3) print $2,$3; else print $2}'`;

     if [ ! -d "../$typedir" ]
     then
	 mkdir "../$typedir"
     fi
     mv -i $i ../$typedir/
     typedir=""
     
done

exit 0
