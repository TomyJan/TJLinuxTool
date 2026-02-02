# TJLinuxTool

## 鉴权管理脚本

管理系统中已有的密钥, 创建新用户, 修改SSH配置以禁止密码登录

脚本必须使用 root 用户运行

默认, 交互模式运行: 
```bash
bash <(curl -sSL https://raw.githubusercontent.com/TomyJan/TJLinuxTool/master/auth-manager.sh)
```
半自动模式运行, 可选传入公钥和用户名: 
```bash
bash <(curl -sSL https://raw.githubusercontent.com/TomyJan/TJLinuxTool/master/auth-manager.sh) -m sequential -p "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC3V..." -u username
```
