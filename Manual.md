## 插件安装
1. 手机必须安装面具
2. 在magisk manager中安装riru插件，riru版本23+
3. 在magisk manager中安装riru-xcube-v1.0.zip，重启手机

## 插件使用
1. 在手机/data/local/tmp/pkg.conf中写入要hook的目标应用包名，每个包名一行,例如:
```
com.tencent.mtt
com.tencent.qq
```
2. 将frida hook用的js脚本重命名放到/data/local/tmp/myscript.js
3. 启动目标应用