#!/bin/bash

# Policy Uploader/Validator for CI/CD
#
# Changelog V1:
#	+	Initial release
# Changelog V2:
#	-	remove metadata generation
# Changelog V3:
#       +       Added metadata generation from policy inherited metadata (for azure policies)
# Changelog V4(beta):
#       +       Added metadata generation (for aws config)
#


##### Functions

usage()
{
    echo "usage: $0 <private git url> <git branch>"
    echo "ex:) $0 https://github.com/sabace/policies.git development"
}

createazurepolicymeta()
{
contentstring=`python $SCPATH/json2string.py "$fname/$file"_policy.json` 
name=`echo $file`
dname=`echo $file|sed 's/_/ /g'`
poldesc=`jq -r '.metadata.policy_description' "$fname/$file"_policy.json`
polid=`jq -r '.metadata.policy_id' "$fname/$file"_policy.json`
classify=`jq -r '.metadata.classification' "$fname/$file"_policy.json`
subclassify=`jq -r '.metadata.sub_classification' "$fname/$file"_policy.json`
sev=`jq -r '.metadata.severity' "$fname/$file"_policy.json`
uriid=`cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 5 | head -n 1`
if [ "`jq -r '.metadata.uri' "$fname/$file"_policy.json`" == "" ]
then
	uri="policy/azure_policy/global/azure/compliance/others/$uriid"
else
	uri=`jq -r '.metadata.uri' "$fname/$file"_policy.json`
fi

if [ "$poldesc" == "" ]
then
	poldesc=$dname
fi

echo '{
  "name": '"\"$name\""',
  "policy_id": '"\"$polid\""',
  "display_name": '"\"$dname\""',
  "description": '"\"$poldesc\""',
  "category": "service",
  "status": "active",
  "content": '$contentstring',
  "parameters": {},
  "classification": '"\"$classify\""',
  "sub_classification": '"\"$subclassify\""',
  "resource_type": [],
  "severity": '"\"$sev\""',
  "type": [
    "Cloud"
  ],
  "services": [
    "Azure"
  ],
  "scope": "global",
  "metadata": {},
  "resources": [],
  "is_temp": false,
  "is_system_policy": false,
  "recommendations": [
    '"\"$name\""'
  ],
  "uri": '"\"$uri\""'
}
' > $fname/$file.json

for var in `jq -r '.metadata.resource_type[]' "$fname/$file"_policy.json 2>/dev/null`
do
	jq --arg var $var '.resource_type[.resource_type| length] |= . + $var' $fname/$file.json > "$fname/$file"_tmp.json; mv "$fname/$file"_tmp.json $fname/$file.json
done

for var in `jq -r '.metadata.resources[]' "$fname/$file"_policy.json 2>/dev/null`
do
        jq --arg var $var '.resources[.resources| length] |= . + $var' $fname/$file.json > "$fname/$file"_tmp.json; mv "$fname/$file"_tmp.json $fname/$file.json
done

uri=`jq -r '.uri' $fname/$file.json`
jq --arg var $uri '.metadata.uri = $var' "$fname/$file"_policy.json > "$fname/$file"_tmp.json; mv "$fname/$file"_tmp.json "$fname/$file"_policy.json

}

createawspolicymeta()
{
#contentstring=`python $SCPATH/json2string.py "$fname/$file"_policy.json`
name=`echo $file`
dname=`echo $file|sed 's/_/ /g'`
poldesc=`jq -r '.description' "$fname"/csmetadata.json`
classify=`jq -r '.classification' "$fname"/csmetadata.json`
subclassify=`jq -r '.sub_classification' "$fname"/csmetadata.json`
sev=`jq -r '.severity' "$fname"/csmetadata.json`
uriid=`cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 5 | head -n 1`
if [[ "`jq -r '.uri' "$fname"/csmetadata.json`" == "" || "`jq -r '.uri' "$fname"/csmetadata.json`" == "null" ]]
then
        uri="policy/aws_config/global/guest/compliance/server/$uriid"
else
        uri=`jq -r '.uri' "$fname"/csmetadata.json`
fi

if [ "$poldesc" == "" ]
then
        poldesc=$dname
fi

if [ "$ptype" == "managed" ]
then
	polpath=AWS/config/managed/$file
else
	polpath=AWS/config/custom/$file
fi


echo '{
  "name": '"\"$name\""',
  "display_name": '"\"$dname\""',
  "description": '"\"$poldesc\""',
  "category": "service",
  "status": "active",
  "content_type": "git",
  "content_url": "<insert git url>",
  "content_path": '"\"$polpath\""',
  "content_password_or_key": "<insert git password here>",
  "content_branch": '"\"$git_branch\""',
  "content_username": "<insert git account>",
  "classification": '"\"$classify\""',
  "sub_classification": '"\"$subclassify\""',
  "services": [
    "AWS"
  ],
  "type": [
    "cloud"
  ],
  "resource_type": [],
  "severity": '"\"$sev\""',
  "scope": "global",
  "metadata": {
  },
  "resources": [],
  "is_temp": false,
  "is_system_policy": false,
  "engine_type": "aws_config",
  "recommendations": [
    '"\"$name\""'
  ],
  "uri": '"\"$uri\""'
}' > $fname/$file.json

for var in `jq -r '.resource_type[]' "$fname"/csmetadata.json 2>/dev/null`
do
        jq --arg var $var '.resource_type[.resource_type| length] |= . + $var' $fname/$file.json > "$fname/$file"_tmp.json; mv "$fname/$file"_tmp.json $fname/$file.json
done

uri=`jq -r '.uri' $fname/$file.json`
jq --arg var $uri '.uri = $var' "$fname"/csmetadata.json > "$fname/$file"_tmp.json; mv "$fname/$file"_tmp.json "$fname"/csmetadata.json
}

createchefmeta()
{

$SCPATH/yaml2json_linux_amd64 < $fname/inspect.yml > $fname/inspect.json
rbfile=`ls $fname/controls|head -1`
rbstring=`python $SCPATH/json2string.py $fname/controls/$rbfile`
jq -n --arg rbstring "$rbstring" '{"script":$rbstring}' > $fname/control.json

contentstring=`python $SCPATH/json2string.py $fname/control.json`
name=`jq -r '.metadata.name' $fname/inspect.json`
dname=`jq -r '.metadata.display_name' $fname/inspect.json`
poldesc=`jq -r '.metadata.description' $fname/inspect.json`
catype=`jq -r '.metadata.category' $fname/inspect.json`
classify=`jq -r '.metadata.classification' $fname/inspect.json`
subclassify=`jq -r '.metadata.sub_classification' $fname/inspect.json`
sev=`jq -r '.metadata.severity' $fname/inspect.json`
scope=`jq -r '.metadata.scope' $fname/inspect.json`
recomm=`jq -r '.metadata.recommendations[]' $fname/inspect.json|head -1`
uri=`jq -r '.metadata.uri' $fname/inspect.json`
os=`jq -r '.metadata.operating_system[0]' $fname/inspect.json`
restype=`jq -r '.metadata.resource_type[0]' $fname/inspect.json`


echo '{
  "name": '"\"$name\""',
  "display_name": '"\"$dname\""',
  "description": '"\"$poldesc\""',
  "category": '"\"$catype\""',
  "status": "active",
  "content": '$contentstring',
  "parameters": {},
  "classification": '"\"$classify\""',
  "sub_classification": '"\"$subclassify\""',
  "operating_system": [
    '"\"$os\""'
  ],
  "resource_type": [ '"\"$restype\""' ],
  "severity": '"\"$sev\""',
  "scope": '"\"$scope\""',
  "metadata": {
  },
  "resources": [],
  "is_temp": false,
  "is_system_policy": false,
  "engine_type" : "chef_inspec",
  "uri": '"\"$uri\""',
  "recommendations": [
    '"\"$recomm\""'
  ]
}' > $fname/$file.json
}

##### Main

#WDIR=/var/tmp/corestack-templates
SCPATH="`dirname \"$0\"`"
SCPATH="`( cd \"$SCPATH\" && pwd )`"
echo "$SCPATH"

# Verify GIT and differences with local repo
git_url=$1
git_branch=$2
wpath=$3

#git_token=$3
#if [ -n $git_token ]
#then
#	org=`echo $git_url|awk -F"/" '{print $(NF-1)}'`
#	gitpath=`echo $git_url|awk -F: '{print $NF}'|awk -F"/" '{print $(NF-1)"/"$NF}'`
#	git_url="https://$org:$git_token@github.com/$gitpath"
#fi

if [[ ! -n "$git_url" || ! -n "$git_branch" ]]
then
	usage
	exit
fi

gitpath=`echo $git_url|awk -F: '{print $NF}'|awk -F"/" '{print $(NF-1)"_"$NF}'`
tempath=`echo "$gitpath"_$git_branch`
WDIR=/var/tmp/$tempath

echo "Using GIT repo: $git_url"

if [ ! -d $WDIR ]
then
	cd /var/tmp;git clone $git_url -b $git_branch $tempath
else
	cd $WDIR; git fetch origin $git_branch; git diff origin/$git_branch|egrep -i "\-\-\-"|cut -d'/' -f2-|rev|cut -d "/" -f 2-|rev |uniq|grep -v dev|grep -v "\-\-\-" > /var/tmp/a
	git diff $git_branch origin/$git_branch|egrep -i "\-\-\-"|awk -F/ '{print $(NF-1)}'|uniq|grep -v dev > /var/tmp/b
	cd $WDIR; git fetch --all; git reset --hard origin/$git_branch; git pull
fi

# Create/Update Policies Sync to GIT
for fname in `cat /var/tmp/a`
do
	fname=`echo $fname|sed 's/\/$//'`
	wname=$fname
	file=`echo $fname|awk -F/ '{print $NF}'`
	ptype=`echo $fname|awk -F/ '{print $(NF-1)}'`
	cpath="/$fname/$file"_content.json
	cpath=`echo $cpath|sed 's/\//%2F/g'`
	fname=$WDIR/$fname
	echo "Determined template path: $fname"	
	echo "Determined template name: $file"
	echo "Checking template folder location ... "

	echo "$fname/$file"_policy.json
	if [ -f "$fname/$file"_policy.json ]
	then
		echo "Policy file detected"
		if [ "$ptype" == "azurepolicy" ]
		then
			echo "Detected azure policy"
			createazurepolicymeta
		fi
#		if [ "$ptype" == "config" ]
#		then
#			echo "Detected aws policy"
#			createawspolicymeta
#		fi
	else
		echo "Policy file undetected"
		echo "Looking for congress policy ..."
		if [ "$ptype" == "congress" ]
                then
			echo "Detected congress policy"
                fi
		if [ "$ptype" == "ChefInspec" ]
		then
			echo "Detected ChefInspec Policy"
			createchefmeta
#			cp /tmp/$file.json "$fname/$file".json
		fi
	fi

        if [[ "$ptype" == "config" || "$ptype" == "managed" || "$ptype" == "custom" ]]
        then
                echo "Detected aws policy"
                createawspolicymeta
        fi



	echo "Uploading Policy ..."
	sudo /usr/bin/python $SCPATH/resource_loader.py http://devserver.corestack.io:18080/v1 admin <insert password here> policy $fname/ A --update
	if [ -f "$fname/$file"_policy.json ]
	then
		cp "$fname/$file"_policy.json "$wpath/$wname/$file"_policy.json
	fi
	if [ "$ptype" == "azurepolicy" ]
        then
		cp "$fname/$file".json "$wpath/$wname/$file".json
	fi
	if [ -f "$fname"/csmetadata.json ]
	then
		cp "$fname"/csmetadata.json "$wpath/$wname"/csmetadata.json
	fi
	sed -i "/$file/d" /var/tmp/b
done

# Remove templates that are not in GIT
#for fname in `cat /var/tmp/b`
#do
	echo "Removing template $fname..."
#done

# Sync local repo with GIT
cd $WDIR; git fetch --all; git reset --hard origin/$git_branch; git pull
