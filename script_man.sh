#!/bin/bash

gzip -cd /usr/share/man/man2/*.gz > prototype.txt
grep -E -w '(\.BI\ \"|",)[\n\.\_(\" \\n,*0-9A-Za-z]*[);|,|\]' prototype.txt | sed "s/\.BI\ \"//g" > prototype2.txt
sed "s/\"//g" < prototype2.txt > prototype3.txt

#tr -d '.BI\ \"' < prototype2.txt > prototype3.txt
