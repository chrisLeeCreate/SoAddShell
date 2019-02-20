##########################################
##                                      ##
##     $1  version 版本号                ##
##     $2  enveriment 环境               ##
##                                      ##
##########################################

if [ $2 == "Release" ]
then
#上一次版本号和git提交commitid 
{ # try
    commitIdOld=$(awk 'NR==1{print}'  version.txt)
    versionOld=$(awk 'NR==2{print}'  version.txt)
} || { # catch
    echo "init" > version.txt
}

#新的版本号和git提交commitId
version=$1
commitId=$(git rev-parse HEAD)
#打印输出
echo $commitIdOld
echo $versionOld
echo $commitId
echo $version

#判断版本号和commitId逻辑
if [ "${commitId}" != "${commitIdOld}" ]
then
    if [ "${version}" == "${versionOld}" ]
    then
        echo "有新的代码提交 需要增加versionCode"
        exit 1
    fi
fi
#保存最新的版本和commitId
git rev-parse HEAD > version.txt
echo $version >> version.txt
fi

