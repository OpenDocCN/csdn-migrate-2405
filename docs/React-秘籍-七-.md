# React 秘籍（七）

> 原文：[`zh.annas-archive.org/md5/AADE5F3EA1B3765C530CB4A24FAA7E7E`](https://zh.annas-archive.org/md5/AADE5F3EA1B3765C530CB4A24FAA7E7E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：部署到生产环境

在这一章中，将涵盖以下内容：

+   在 Digital Ocean 上部署到生产环境

+   在我们的 Droplet 中配置 Nginx、PM2 和域名

+   实施 Jenkins（持续集成）

# 介绍

如果你正在阅读这一章，很可能是因为你已经完成了你的 React 应用程序（恭喜！）。现在是时候将其部署到生产环境并展示给世界了。在这一章中，我们将学习如何使用最好的云服务之一——Digital Ocean 来部署我们的 React 应用程序。

在这一点上，你需要投资一些钱来租用你需要的服务器。我会向你展示最便宜的方法来做到这一点，然后，如果你想增加服务器的功率，你将能够在不重新配置的情况下做到这一点。

# 在 Digital Ocean 上部署到生产环境

Digital Ocean 是我最喜欢的云计算平台，因为它非常容易创建、配置和删除 droplets，并且价格低廉（你可以每月得到一个 droplet，每月只需 5 美元，也就是每小时 0.007 美元）。我认为 Digital Ocean 很棒的另一个原因是他们的所有文档都是最新的，客户服务也很快解决你可能遇到的任何问题。

对于这个步骤，我们将使用 Ubuntu 18.04，所以你需要了解一些基本的 Linux 命令来配置你的 droplet。如果你完全是新手，不用担心，我会尽量以简单的方式解释每一步。

# 准备工作

首先，你需要创建你的 Digital Ocean 账户，访问[`www.digitalocean.com`](https://www.digitalocean.com)。你可以使用你的 Google 账户注册；这是推荐的方式。一旦你点击使用 Google 注册的链接，你将看到账单信息视图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/8f8fae15-2381-4f91-94ab-7f7d0a46cf88.png)

你可以注册你的信用卡/借记卡，或者你可以使用 PayPal 支付。一旦你配置好你的付款信息，你就可以创建你的第一个 Droplet 了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/b4c53373-cdae-4b83-8142-c0dbefd1d8d3.png)

# 如何做...

让我们创建我们的第一个 Droplet：

1.  选择你的 Linux 发行版；正如我之前提到的，我们将使用 Ubuntu 18.04：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/1c1ba873-4484-48ec-bc49-083128a57b58.png)

1.  一键应用是预配置的 Droplet，但我更喜欢从头开始设置我的 Droplet，以便拥有控制权并能够优化我的配置。在此之后，如果您需要快速配置某些内容，可以查看这些选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/824561cf-fc0a-4eb7-a845-1f62c5013887.png)

1.  选择您的 Droplet 的大小。我更喜欢使用 2GB 内存的 Droplet，每月费用为*10 美元*。也许您会想为什么我不选择最便宜的 1GB 内存版本；这是因为我曾尝试使用这个版本，但我注意到*1GB 内存*不足以处理安装包时的 NPM。大多数情况下，这会使您的 Droplet 挂起——我知道这听起来很荒谬，但 NPM 消耗大量内存。

1.  如果您选择了 10 美元的 Droplet，您不必立即支付这笔钱。Digital Ocean 最好的一点是他们只会按您使用 Droplet 的时间收费。这意味着如果在完成此操作后（假设您花了 2 小时来完成它），您关闭（关机）您的 Droplet，您只会被收取 2 小时的费用，即*0.030 美元*。如果您将 Droplet 保持开启一个月（30 天），您将被收取 10 美元，所以不用担心：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/e497ef00-ce89-42a0-8f8b-2e23c4aaf03c.png)

1.  选择数据中心区域；这将取决于您的位置。如果您在美国，您需要选择纽约或旧金山。您需要选择距离您位置最近的数据中心：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/2fa45903-37ae-4830-857f-3442ef6c4e15.png)

1.  给您的 Droplet 命名。如果您需要多个 Droplet，您可以在这里选择数量：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/afe71907-6d57-4cbe-864b-d3a9044da95b.png)

1.  点击“创建”按钮后，将需要 30-45 秒来创建您的 Droplet。完成后，您将看到您的 Droplet：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/9a33a693-4dd4-45ce-a9db-33f5c7d1a017.png)

1.  此时，您应该会收到一封包含服务器凭据的电子邮件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/613317ad-ef62-4ac4-bcc4-21caadd6f037.png)

1.  在您的终端中，您可以使用`ssh root@YOUR_DROPLET_IP`命令访问您的 Droplet。第一次访问时，您将收到一条消息，要求将此 IP 添加到已知主机中，然后您需要输入 Droplet 密码：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/222f41e9-aa44-457b-b655-8d4d1e1a40de.png)

1.  如果一切正常，您将被要求更改您的 UNIX 密码。您需要粘贴当前密码，然后输入您想要的新密码并重新输入，之后您将连接到 Droplet：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/77529c96-f24a-4630-8329-fb4393c3d839.png)

1.  让我们开始配置我们的 Droplet。安装 Node.js。为此，我们将使用 PPA 安装 Node 的最新版本。现在，Node 的当前版本是 10.x。如果在阅读此配方时，Node 有一个新版本，请在命令中更改版本（setup_**10.x**）：

```jsx
  cd ~
  curl -sL https://deb.nodesource.com/setup_10.x -o nodesource_setup.sh
```

1.  一旦我们得到`nodesource_setup.sh`文件，运行以下命令：

```jsx
 ** sudo bash** **nodesource_setup.sh**
```

1.  要安装 Node，请运行以下命令：

```jsx
 **sudo apt** **install** **nodejs -y**
```

1.  如果您想验证刚刚安装的 Node 和 NPM 的版本，请运行：

```jsx
 node -v
 v10.8.0
 npm -v
 6.2.0
```

# 它是如何工作的...

使用我们在第十一章中执行的一些配方，*实施服务器端渲染*，我创建了一个新的 GitHub 存储库，并将该代码推送到生产环境。您可以在[`github.com/csantany/production`](https://github.com/csantany/production)上看到这个存储库。

在我们的 Droplet 中，我们将克隆此 git 存储库（如果您已经准备好您的应用程序，请使用您的存储库）。生产存储库是公开的，但如果您使用私人存储库，则需要在 GitHub 帐户中添加 Droplet 的 SSH 密钥。为此，您需要在 Droplet 中运行`ssh-keygen`命令，然后按三次*Enter*而不写任何密码：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/7fafb0c4-915a-44c5-b855-09d9f774f20c.png)如果您的终端在五分钟内处于非活动状态，可能会关闭您的连接，您将不得不重新连接。

创建 SSH 密钥后，您可以通过执行以下操作查看它：`vi /root/.ssh/id_rsa.pub`。您需要复制 SSH 密钥并转到您的 GitHub 帐户|设置|SSH 和 GPG 密钥（[`github.com/settings/ssh/new`](https://github.com/settings/ssh/new)）。然后将密钥粘贴到文本区域中，并为密钥添加一些标题。单击“添加 SSH 密钥”按钮时，GitHub 将要求您输入密码以确认：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/6e77806f-e1e7-458d-b631-54cdc21f5fea.png)

现在我们可以使用`git clone git@github.com:csantany/production.git`克隆我们的存储库，或者您的存储库：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/8f5aa495-a4c3-4fb7-8620-9a4e30075111.png)

然后转到生产文件夹并安装 NPM 包：

```jsx
    cd production
 npm install
```

要测试我们的应用程序，让我们运行 npm run start-production 脚本：

```jsx
    npm run start-production
```

如果您想验证它是否有效，请转到浏览器并打开 Droplet 的 IP，然后添加端口 3000—在我的情况下将是`http://178.128.177.84:3000`，如果一切正常，您应该看到您的应用程序（在我们的情况下，我们将打开我们的/todo 部分）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/5f8932eb-4163-4242-90d8-a41ae0f6406d.png)

# 还有更多...

如果您想关闭您的 Droplet，您可以转到电源部分，或者您可以使用开/关开关：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/08a46a15-3719-4104-8840-a481e8ff6aeb.png)

当您点击它时，您将会得到这个模态框：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/920bcbcf-98ca-440b-a62d-68efe72a3eb2.png)

# 配置 Nginx、PM2 和 Droplet 中的域

在这一点上，我们的第一个 Droplet 已经准备好使用，但我们可以看到我们的 React 应用程序使用端口 3000。在这个配方中，我们将学习如何在服务器上配置 Nginx 以及如何实现代理将流量从端口 80 重定向到 3000。这意味着我们不再需要直接指定我们的端口。PM2（Node 生产进程管理器）将帮助我们在生产环境中安全地运行我们的 Node 服务器。通常，如果我们直接使用`node`或`babel-node`命令运行 Node，并且我们的应用程序出现错误，它将崩溃并停止工作；如果发生错误，PM2 将重新启动 Node 服务器。

# 准备就绪

对于这个配方，我们需要全局安装 PM2：

```jsx
 npm install -g pm2
```

此外，我们需要安装 Nginx：

```jsx
 sudo apt-get update
    sudo apt-get install nginx
```

# 如何做...

让我们从配置开始：

1.  调整防火墙以允许流量只通过端口 80。要列出可用的应用程序配置，我们运行以下命令：

```jsx
   **sudo** **ufw app list**

  ** Available applications:**
     ** Nginx Full**
 **Nginx HTTP**
 **Nginx HTTPS**
 **OpenSSH** 
```

1.  `Nginx Full` 意味着我们将允许端口 80（HTTP）和 443（HTTPS）的流量。在这一点上，我们还没有为 SSL 配置任何域，所以我们应该限制流量只通过端口 80（HTTP）传递：

```jsx
   **sudo ufw allow** **'Nginx HTTP'**
```

1.  如果我们尝试访问我们的 IP，我们应该看到我们的 Nginx 正在工作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/96aeb8a7-c9df-4a2e-a032-a14d3c119f78.png)

1.  如果您想管理 Nginx 的进程，您可以使用这些命令：

+   **启动服务器**：`sudo systemctl start nginx`

+   **停止服务器**：`sudo systemctl stop nginx`

+   **重新启动服务器**：`sudo systemctl restart nginx`

+   **重新加载服务器**：`sudo systemctl reload nginx`

+   **禁用服务器**：`sudo systemctl disable nginx`

1.  设置 Nginx 作为反向代理服务器，为此我们需要打开我们的 Nginx 配置文件：

```jsx
 ** sudo vi** **/etc/nginx/sites-available/default**
```

1.  在`location /`块中，我们需要将其替换为：

```jsx
  location / {
    proxy_pass http://localhost:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_cache_bypass $http_upgrade;
  }
```

# 它是如何工作的...

一旦您保存并关闭文件，我们需要验证是否有任何语法错误。使用以下命令：

```jsx
    sudo nginx -t
```

如果一切正常，您应该看到：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/e92ff470-bb57-4054-bb8d-c8d12206ca11.png)

最后，我们重新启动我们的 Nginx 服务器：

```jsx
 **sudo systemctl restart nginx**
```

现在我们可以访问我们的 IP 而不带端口，React 应用程序将正常工作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/ee2dd4f9-4647-4f69-81c7-5cf1c5feb01d.png)

# 还有更多...

如果您想要在 Droplet 上使用域名，这非常简单；您需要将域名的 Nameservers 更改为指向 Digital Ocean 的 Nameservers。例如，我有一个名为 educnow.com 的域名，我将用于我的 Droplet。我在 Godaddy 注册了这个域名，所以我必须转到域名管理并选择它。您可以直接转到`https://dcc.godaddy.com/manage/YOURDOMAIN.COM/dns` URL。然后转到 Nameservers：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/c9b73e93-bbbe-43aa-8dd0-664b590a2f99.png)

我们必须点击“更改”按钮，选择“自定义”，指定 Digital Ocean Nameservers，并点击“保存”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/a4d29c53-0eaf-4b98-86e1-220386dd5b76.png)

一旦您修改了 Nameservers，您需要转到 Droplet 仪表板并选择“添加域名”选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/fffc047b-5401-4739-b348-c98aff746683.png)

然后输入要链接到 Droplet 的域名，然后单击“添加域名”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/e7161d4b-11cd-4a5e-ad54-9cc9b5ac4dab.png)

现在您需要为 CNAME 创建一个新记录。选择 CNAME 选项卡，在主机名中写入`www`，在别名字段中写入`@`，默认情况下 TTL 为`43200`—这是为了能够使用`www.yourdomain.com`前缀访问您的域名：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/9e417d23-e513-40c0-bbfa-a6c4cc12beb8.png)

如果您一切都做对了，您应该能够访问您的域名并看到您的 React 应用程序正在运行；这个过程可能需要 30 分钟到 24 小时，具体取决于 DNS 传播速度。

# 实施 Jenkins（持续集成）

Jenkins 是最受欢迎的持续集成软件之一，它基于 Java 并且是开源的。

# 准备就绪

运行 Jenkins 有一些先决条件：

+   您需要一个带有 Ubuntu 18 的 Droplet（服务器）。

+   您需要安装 Java 8。

如果您尚未安装 Java 8，可以使用以下命令进行安装：

**sudo apt  install openjdk-8-jre-headless**

如果要检查已安装的 Java 版本，可以使用`java -version`命令：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/95f04dff-edfc-48c0-899a-a61b80e88001.png)

# 如何做到这一点...

现在让我们安装和配置 Jenkins：

1.  将存储库密钥添加到系统中：

```jsx
 **wget -q -O - https://pkg.jenkins.io/debian/jenkins.io.key | sudo apt-key add -**
```

1.  将 Debian 软件包地址追加到`sources.list`：

```jsx
 **sudo sh -c 'echo deb http://pkg.jenkins.io/debian-stable** binary/ **> /etc/apt/sources.list.d/jenkins.list'**
```

1.  更新 apt 软件包：

```jsx
 **sudo apt update**
```

1.  安装 Jenkins：

```jsx
 **sudo apt install jenkins**
```

如果在安装 Jenkins 时出现错误，可以使用以下命令卸载它：

**sudo apt-get remove --purge** jenkins

1.  启动 Jenkins 服务：

```jsx
 sudo systemctl start jenkins
```

1.  如果您想查看 Jenkins 状态，请使用此命令：

```jsx
 **sudo systemctl status jenkins**
```

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/69f18ccf-68ff-4f58-93c9-e38b13fb3bf4.png)

1.  Jenkins 默认运行在端口 8080 上，我们需要打开防火墙以允许流量通过该端口：

```jsx
 **sudo ufw allow 8080**
```

1.  如果你想验证防火墙状态，执行以下操作：

```jsx
    **sudo ufw status**
```

如果你看到状态：inactive，你需要运行以下命令来启用防火墙：

**sudo ufw allow OpenSSH**

**sudo ufw enable**![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/5fabecf9-a272-4600-9e22-63c91f688307.png)

1.  是时候第一次运行并配置我们的 Jenkins 了。为此，你需要访问 `http://<your_droplet 的 IP 或域名>:8080`。在我的情况下，是 `http://142.93.28.244:8080`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/67584010-d8f9-49d9-8792-bee9c0b9590f.png)

1.  要查看第一个密码，你需要运行：

```jsx
**sudo cat /var/lib/jenkins/secrets/initialAdminPassword**
```

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/a8c88760-d80d-4c1f-95e3-ed10c859a8b1.png)

1.  你会看到欢迎来到 Jenkins 页面。你需要选择“安装建议的插件”选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/a28bf925-13bb-4449-a388-dcce812e15d7.png)

1.  你会看到安装过程：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/ef348693-d084-43cd-be6e-4c43ea7f06b1.png)

1.  安装完成后，你需要创建第一个管理员用户：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/450336d6-a3ed-4426-be31-528e8930cc5b.png)

1.  确认 Jenkins URL 如果你不想更改它。点击保存并完成：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/67f5dcc1-99f8-44b6-abbf-e33585f16c4b.png)

1.  Jenkins 已准备就绪：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/7b53bde8-416c-42aa-8a12-aabe46c244a5.png)

1.  你在 Jenkins 中看到的第一个视图是这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/ea8373a4-57bb-43ea-a183-b8702e06d8e8.png)

1.  转到“管理 Jenkins” > “管理插件”来安装 GitHub 插件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/4acca626-b933-4331-bab3-bf6fe79ff541.png)

1.  选择“可用”选项卡，然后搜索 GitHub 集成。现在选择复选框选项，然后点击“立即下载并在重启后安装”按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/7e644e93-7b21-4f33-b7bd-1683f5bb8a13.png)

1.  选择“安装完成后重新启动 Jenkins，且没有任务正在运行”选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/b679bd1e-c7ea-4cc4-8d46-42a6208719db.png)

1.  你会看到这个消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/907880ac-a25e-4a96-8ea5-41d971742a9a.png)

1.  等待一分钟，然后刷新页面。你可能需要重新登录。

1.  返回到“管理插件”；现在你需要安装“后构建任务插件”。

1.  我们可以通过在主页上点击创建新任务来创建我们的第一个任务：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/666ea3f7-cb57-48ed-b6e1-fc91453d3a0f.png)

1.  输入你的任务名称，选择自由风格项目选项，然后点击确定按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/3064e63b-656d-4224-8576-9bc1ba74e473.png)

1.  在常规配置中，转到源代码管理部分，选择 Git 选项，然后写入你的 GitHub 项目 HTTPS URL（如果选择 SSH URL，你需要在 GitHub 中为 Jenkins 添加新的 SSH 密钥）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/84650f9d-e6be-41c1-986d-09270726558c.png)

1.  如果你的存储库是私有的，你需要点击“添加”按钮来指定你的 GitHub 凭据（用户名和密码）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/fa606801-d577-4aa7-bdf0-6523a10b516f.png)

1.  选择你的凭据，并确保`master`分支被选为你的主分支（建议使用主分支而不是其他分支）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/2fd8c743-7f10-4686-91cb-04276161c890.png)

1.  在后构建操作中选择“后构建任务”选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/d6803c1b-e91b-4058-95ba-34f638811ca4.png)

1.  在文本框脚本中，添加`npm install && npm run start-production`。点击应用，然后点击保存按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/93173b99-a56f-4164-b1a8-de7c0631bd04.png)

# 它是如何工作的...

我们已经配置好了 Jenkins 作业，现在让我们来测试一下。我将修改一个简单的文件，以确保 Jenkins 正常工作。

到这一步（如果你按照第一个教程操作），你必须使用命令“**npm run stop**”停止 PM2 服务器，然后删除之前克隆的生产目录，以避免与 Jenkins 作业出现问题。

让我们修改我们的主页组件；我会添加额外的文本**(Jenkins)**：

```jsx
  import React from 'react';
  import styles from './Home.scss';

  const Home = props => (
    <h1 className={styles.Home}>Hello {props.name || 'World'} (Jenkins)</h1>
  );

  export default Home;
```

文件：src/client/home/index.jsx

之后，你需要提交并推送到主分支。现在转到 Jenkins，选择你的作业，然后点击“立即构建”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/4cee1644-935c-4e1d-9011-28768649a40f.png)

之后，点击最新的构建（在我的情况下是＃5，因为我之前做了一些测试，但对你来说，它将是＃1）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/fbc52eb4-7bc8-495d-96c1-90149b6a8160.png)

在构建中，你会看到是谁（用户）启动了构建，正在构建的是哪个修订版本（主分支的最新提交）。如果你想查看控制台输出，你可以点击左侧菜单中的选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/5710a5c8-b283-4954-8bc2-d75b2b3f2d57.png)

如果你查看控制台输出，你会看到大量的命令：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/f271e88e-6e1d-455d-b663-b963aacf2109.png)

每次运行新构建时，Jenkins 都会获取存储库的最新更改：

```jsx
 git config remote.origin.url https://github.com/csantany/production.git
```

然后将获取主分支的最新提交：

```jsx
 git rev-parse refs/remotes/origin/master^{commit}
```

最后，它将执行我们在后构建任务中指定的命令：

```jsx
 npm install && npm run start-production
```

如果一切正常，你应该在输出的末尾看到“完成：成功”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/6bfadaed-70c9-42f4-b96a-2ac414cce03a.png)

现在等待 30 秒或 1 分钟，然后访问你的生产网站（在我的案例中是`http://142.93.28.244/`）- 你会看到新的改变：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/9b5b1bed-835a-4774-bfd8-5f53ac5e0963.png)

如果你想知道文件存储在哪里，你可以在`/var/lib/jenkins/workspace/<your_jenkins_job_name>`看到它们。


# 第十四章：使用 React Native

在本章中，将涵盖以下内容：

+   创建我们的第一个 React Native 应用程序

+   用 React Native 创建一个待办事项列表

+   实现 React Navigation V2

# 介绍

React Native 是使用 JavaScript 和 React 构建移动应用程序的框架。许多人认为使用 React Native 可以制作一些"移动 Web 应用程序"或"混合应用程序"（如 Ionic、PhoneGap 或 Sencha），但实际上你构建的是原生应用程序，因为 React Native 将你的 React 代码转换为 Android 的 Java 代码或 iOS 应用程序的 Objective-C 代码。React Native 使用了大部分 React 的概念，如组件、属性、状态和生命周期方法。

**React Native 的优势**：

+   你只需编写一次代码，就可以得到两个原生应用程序（Android 和 iOS）

+   你不需要有 Java、Objective-C 或 Swift 的经验

+   更快的开发

+   MIT 许可证（开源）

**Windows 的要求**：

+   Android Studio

+   Android SDK（>= 7.0 Nougat）

+   Android AVD

**Mac 的要求**：

+   XCode（>= 9）

+   模拟器

# 创建我们的第一个 React Native 应用程序

在这个教程中，我们将构建一个 React Native 应用程序，并了解 React 和 React Native 之间的主要区别。

# 准备工作

要创建我们的新的 React Native 应用程序，我们需要安装`react-native-cli`包：

```jsx
 npm install -g react-native-cli
```

# 如何做...

现在，要创建我们的第一个应用程序：

1.  让我们用这个命令来做：

```jsx
    react-native init MyFirstReactNativeApp
```

1.  在我们构建了 React Native 应用程序之后，我们需要安装 Watchman，这是 React Native 所需的文件监视服务。要安装它，去[`facebook.github.io/watchman/docs/install.html`](https://facebook.github.io/watchman/docs/install.html)下载最新版本适合你的操作系统（Windows、Mac 或 Linux）。

1.  在这种情况下，我们将使用 Homebrew 在 Mac 上安装它。如果你没有 Homebrew，你可以用这个命令安装它：

```jsx
    /usr/bin/ruby -e "$(curl -fsSL 
  https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

1.  要安装 Watchman，你需要运行：

```jsx
    brew update 
    brew install watchman
```

1.  要启动 React Native 项目，我们需要使用：

```jsx
    react-native start
```

1.  如果一切正常，你应该看到这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/e35eac32-1884-4536-a5f9-54f4da4d66f4.png)

有时你可能会从 Watchman 得到错误，例如，

Watchman 错误：太多待处理的缓存作业。确保 watchman 正在为此项目运行。

如果你遇到了这个错误或其他错误，你需要通过以下方式卸载 Watchman：

`brew unlink watchman`

然后重新安装：

`brew update && brew upgrade`

`brew install watchman`

1.  打开一个新的终端（*Cmd* + *T*）并运行这个命令（取决于你想要使用的设备）：

```jsx
    react-native run-ios 
    or
    react-native run-android
```

1.  如果没有错误，您应该看到模拟器运行默认应用程序：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/c3401446-ceb5-4e10-b3cf-05035956e486.png)

现在我们的应用程序正在运行，让我们打开我们的代码并稍微修改一下：

1.  更改`App.js`文件：

```jsx
  ...
  export default class App extends Component<Props> {
    render() {
      return (
        <View style={styles.container}>
          <Text style={styles.welcome}>
 This is my first React Native App!          </Text>
          <Text style={styles.instructions}>
            To get started, edit App.js
          </Text>
          <Text style={styles.instructions}>{instructions}</Text>
        </View>
      );
    }
  }
  ...
```

文件：App.js

1.  如果您再次进入模拟器，您需要按下*Cmd* + *R*重新加载应用程序以查看新更改的反映：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/7eee4328-9e21-4817-aa7b-509f29d091eb.png)

1.  你可能想知道是否有一种自动重新加载的方法，而不是手动进行这个过程，当然，有一种方法可以启用实时重新加载选项；您需要按下*Cmd* + *D*打开开发菜单，然后选择启用实时重新加载选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/bb6d8d70-44a2-46a2-ab0f-056639812a61.png)

1.  另一个令人兴奋的选项是远程调试 JS。如果您点击它，它将自动打开一个 Chrome 标签，我们可以在那里看到我们使用`console.log`添加到我们的应用程序的日志。例如，如果我在我的渲染方法中添加`console.log('====调试我的第一个 React Native 应用！====');`，我应该看到它像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/a3c376a1-cb8c-43fe-8892-5b62157c4b6c.png)

1.  让我们回到代码。也许您对在`App.js`中看到的代码有点困惑，因为您没有看到`<div>`标签，甚至更糟糕的是样式的创建方式像是一个对象，而不是像我们在 React 中使用 CSS 文件。我有一些好消息和一些坏消息；坏消息是 React Native 不支持 CSS 和 JSX/HTML 代码，就像 React 一样。好消息是，一旦您理解了`<View>`组件相当于使用`<div>`，`<Text>`相当于使用`<p>`，样式就像 CSS 模块（对象），其他一切都与 React 相同（props，state，生命周期方法）。

1.  创建一个新的组件（`Home`）。为此，我们必须创建一个名为 components 的目录，然后将此文件保存为`Home.js`：

```jsx
  // Dependencies
  import React, { Component } from 'react';
  import { StyleSheet, Text, View } from 'react-native';

  class Home extends Component {
    render() {
      return (
        <View style={styles.container}>
          <Text style={styles.home}>Home Component</Text>
        </View>
      );
    }
  }

  const styles = StyleSheet.create({
    container: {
      flex: 1,
      justifyContent: 'center',
      alignItems: 'center',
      backgroundColor: '#F5FCFF',
    },
    home: {
      fontSize: 20,
      textAlign: 'center',
      margin: 10,
    }
  });

 export default Home;
```

文件：components/Home.js

1.  在`App.js`中，我们导入`Home`组件，并将其渲染出来：

```jsx
  // Dependencies
  import React, { Component } from 'react';
  import { StyleSheet, Text, View } from 'react-native';

  // Components
  import Home from './components/Home';

  class App extends Component {
    render() {
      return (
        <Home />
      );
    }
  }

  export default App;
```

文件：App.js

# 它是如何工作的...

正如您所看到的，创建一个新的 React Native 应用程序非常容易，但是 React（使用 JSX）和 React Native 之间存在一些关键差异，使用特殊的标记和对象样式，甚至样式也有一些限制，例如，让我们创建一个 flex 布局：

```jsx
    // Dependencies
    import React, { Component } from 'react';
    import { StyleSheet, Text, View } from 'react-native';

    class Home extends Component {
      render() {
        return (
          <View style={styles.container}>
            <View style={styles.header}>
              <Text style={styles.headerText}>Header</Text>
            </View>

            <View style={styles.columns}>
              <View style={styles.column1}>
                <Text style={styles.column1Text}>Column 1</Text>
              </View>

              <View style={styles.column2}>
                <Text style={styles.column2Text}>Column 2</Text>
              </View>

              <View style={styles.column3}>
                <Text style={styles.column3Text}>Column 3</Text>
              </View>
            </View>
          </View>
        );
      }
    }

    const styles = StyleSheet.create({
      container: {
        flex: 1,
        height: 100
      },
      header: {
        flex: 1,
        backgroundColor: 'green',
        justifyContent: 'center',
        alignItems: 'center'
      },
      headerText: {
        color: 'white'
      },
      columns: {
        flex: 1
      },
      column1: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'red'
      },
      column1Text: {
        color: 'white'
      },
      column2: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'blue'
      },
      column2Text: {
        color: 'white'
      },
      column3: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'orange'
      },
      column3Text: {
        color: 'white'
      },
    });

    export default Home;
```

文件：components/Home.js

您可能不喜欢看一个庞大的文件（我也不喜欢），所以让我们将我们的组件和样式分开：

```jsx
  import { StyleSheet } from 'react-native';

  export default StyleSheet.create({
    container: {
      flex: 1,
      height: 100
    },
    header: {
      flex: 1,
      backgroundColor: 'green',
      justifyContent: 'center',
      alignItems: 'center'
    },
    headerText: {
      color: 'white'
    },
    columns: {
      flex: 1
    },
    column1: {
      flex: 1,
      alignItems: 'center',
     justifyContent: 'center',
      backgroundColor: 'red'
    },
    column1Text: {
      color: 'white'
    },
    column2: {
      flex: 1,
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'blue'
    },
    column2Text: {
      color: 'white'
    },
    column3: {
      flex: 1,
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'orange'
    },
    column3Text: {
      color: 'white'
    },
  });
```

文件：components/HomeStyles.js

然后在我们的`Home`组件中，我们可以导入样式并以与以前相同的方式使用它们：

```jsx
  // Dependencies
  import React, { Component } from 'react';
  import { StyleSheet, Text, View } from 'react-native';

  // Styles
  import styles from './HomeStyles';
  ...
```

文件：components/Home.js

这是代码的结果：

！[](assets/143ec48a-2ad7-448b-976e-385f6f5c2ec1.png)

但有一些不寻常的地方。

正如您所看到的，我为`<Text>`组件（headerText，column1Text 等）创建了样式，这是因为某些样式不允许在 View 组件中使用。例如，如果您尝试将`color: 'white'`属性添加到`<View>`组件中，您会发现该属性不起作用，标题将具有黑色文本：

！[](assets/1ddeecf5-b761-499f-87d7-3232e4eff05f.png)

# 使用 React Native 创建待办事项列表

在这个示例中，我们将学习如何在 React Native 中处理事件以及如何通过创建一个简单的待办事项列表来处理状态。

# 如何做...

对于这个示例，我创建了一个名为“MySecondReactNativeApp”的新 React 应用程序：

1.  创建一个`src`文件夹并将`App.js`文件移动到其中。还要修改此文件以包含我们的待办事项列表：

```jsx
  import React, { Component } from 'react';

  import Todo from './components/Todo';

  export default class App extends Component {
    render() {
      return (
        <Todo />
      );
    }
  }
```

文件：src/App.js

1.  我们的`Todo`组件将是：

```jsx
  import React, { Component } from 'react';
  import { 
    Text, 
    View, 
    TextInput, 
    TouchableOpacity, 
    ScrollView 
  } from 'react-native';

  import styles from './TodoStyles';

  class Todo extends Component {
    state = {
      task: '',
      list: []
    };

    onPressAddTask = () => {
      if (this.state.task) {
        const newTask = this.state.task;
        const lastTask = this.state.list[0] || { id: 0 };
        const newId = Number(lastTask.id + 1);

        this.setState({
          list: [{ id: newId, task: newTask }, ...this.state.list],
          task: ''
        });
      }
    }

    onPressDeleteTask = id => {
      this.setState({
        list: this.state.list.filter(task => task.id !== id)
      });
    }

    render() {
      const { list } = this.state;
      let zebraIndex = 1;

      return (
        <View style={styles.container}>
          <ScrollView
            contentContainerStyle={{
              flexGrow: 1,
            }}
          >
            <View style={styles.list}>
              <View style={styles.header}>
                <Text style={styles.headerText}>Todo List</Text>
              </View>

              <View style={styles.add}>
                <TextInput
                  style={styles.inputText}
                  placeholder="Add a new task"
                  onChangeText={(value) => this.setState({ task: 
 value })}
                  value={this.state.task}
                />

                <TouchableOpacity
                  style={styles.button}
                  onPress={this.onPressAddTask}
                >
                  <Text style={styles.submitText}>+ Add Task</Text>
                </TouchableOpacity>
              </View>

              {list.length === 0 && (
                <View style={styles.noTasks}>
                  <Text style={styles.noTasksText}>
                    There are no tasks yet, create a new one!
 </Text>
                </View>
              )}

              {list.map((item, i) => {
                zebraIndex = zebraIndex === 2 ? 1 : 2;

                return (
                  <View key={`task${i}`} style=
                   {styles[`task${zebraIndex}`]}>
                    <Text>{item.task}</Text>
                    <TouchableOpacity onPress={() => { 
                     this.onPressDeleteTask(item.id) }}>
                      <Text style={styles.delete}>
                        X
                      </Text>
                    </TouchableOpacity>
                  </View>
                );
              })}
            </View>
 </ScrollView>
 </View>
      );
    }
  }

 export default Todo;
```

文件：src/components/Todo.js

1.  这是样式：

```jsx
  import { StyleSheet } from 'react-native';

 export default StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: '#F5FCFF',
      height: 50
    },
    list: {
      flex: 1
    },
    header: {
      backgroundColor: '#333',
      alignItems: 'center',
      justifyContent: 'center',
      height: 60
    },
    headerText: {
      color: 'white'
    },
    inputText: {
      color: '#666',
      height: 40,
      borderColor: 'gray',
      borderWidth: 1
    },
    button: {
      paddingTop: 10,
      paddingBottom: 10,
      backgroundColor: '#1480D6'
    },
    submitText: {
      color:'#fff',
      textAlign:'center',
      paddingLeft : 10,
      paddingRight : 10
    },
    task1: {
      flexDirection: 'row',
      height: 50,
      backgroundColor: '#ccc',
      alignItems: 'center',
      justifyContent: 'space-between',
      paddingLeft: 5
    },
    task2: {
      flexDirection: 'row',
      height: 50,
      backgroundColor: '#eee',
      alignItems: 'center',
      justifyContent: 'space-between',
      paddingLeft: 5
    },
    delete: {
      margin: 10,
      fontSize: 15
    },
    noTasks: {
      flex: 1,
      alignItems: 'center',
      justifyContent: 'center'
    },
    noTasksText: {
      color: '#888'
    }
  });
```

文件：src/components/TodoStyles.js

# 它是如何工作的...

在我们的组件中做的第一件事是设置我们的状态。`task`状态是为了创建新项目的输入，`list`状态是为了保存所有任务项目：

```jsx
 state = {
      task: '',
      list: []
    };
```

`TextInput`组件创建一个输入元素，与 React 中的输入的主要区别在于，它使用`onChangeText`而不是`onChange`方法，并且默认获取值，我们可以直接更新我们的状态：

```jsx
 <TextInput
    style={styles.inputText}
    placeholder="Add a new task"
    onChangeText={(value) => this.setState({ task: value })}
    value={this.state.task}
  />
```

`TouchableOpacity`组件用于处理点击事件（在 React Native 中为`onPress`），可以用作按钮。也许您想知道为什么我没有直接使用`Button`组件；这是因为在 iOS 上无法向按钮添加背景颜色，它只能在 Android 上使用背景。使用`TouchableOpacity`（或`TouchableHighlight`），您可以个性化样式，并且它完全可以作为按钮使用：

```jsx
  <TouchableOpacity
    style={styles.button}
    onPress={this.onPressAddTask}
  >
    <Text style={styles.submitText}>+ Add Task</Text>
  </TouchableOpacity>
```

在任务的渲染中，我为任务实现了斑马样式（混合颜色）。此外，我们正在处理`onPressDeleteTask`以通过单击 X 按钮删除每个项目：

```jsx
    {list.map((item, i) => {
      zebraIndex = zebraIndex === 2 ? 1 : 2;

      return (
        <View key={`task${i}`} style={styles[`task${zebraIndex}`]}>
          <Text>{item.task}</Text>
          <TouchableOpacity onPress={() => { 
           this.onPressDeleteTask(item.id) }}>
            <Text style={styles.delete}>
              X
            </Text>
          </TouchableOpacity>
 </View>
      );
    })}
```

如果我们运行应用程序，我们将首先看到这个视图：

！[](assets/2d2f0dae-68e1-4133-8a46-c2c045dc9934.png)

如果我们没有任何任务，我们将看到“目前没有任务，创建一个新任务！”的消息。

如您所见，顶部有一个输入框，其中有“添加新任务”的占位符。让我们添加一些任务：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/95c20111-0c20-4279-8f72-5234768adff0.png)

最后，我们可以通过点击 X 来删除任务；我将删除支付房租任务：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/f9de4d83-f22e-4816-9327-a31a04995b7e.png)

如您所见，通过这个基本的待办事项列表，我们学会了如何在 React Native 中使用本地状态以及如何处理点击和更改事件。

# 还有更多...

如果您想要防止用户意外删除任务，可以添加一个警报，询问用户是否确定要删除所选任务。为此，我们需要从 react-native 导入 Alert 组件并修改我们的 onPressDeleteTask 方法：

```jsx
  import { 
    Text, 
    View, 
    TextInput, 
    TouchableOpacity, 
    ScrollView, 
 Alert 
  } from 'react-native';

  ...

  onPressDeleteTask = id => {
    Alert.alert('Delete', 'Do you really want to delete this task?', [
      {
        text: 'Yes, delete it.',
        onPress: () => {
          this.setState({
            list: this.state.list.filter(task => task.id !== id)
          });
        }
      }, {
        text: 'No, keep it.'
      }
    ]);
  }

  ...
```

如果您运行应用程序并尝试删除任务，您现在将看到这个本机警报：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/16f565c9-3af5-4830-8e61-ee002c1821da.png)

# 实现 React Navigation V2

在这个教程中，我们将学习如何在 React Native 应用程序中实现 React Navigation V2。我们将在部分之间创建一个简单的导航。

# 准备工作

我们需要安装`react-navigation`依赖项：

```jsx
 npm install react-navigation
```

# 如何做到...

让我们实现 React Navigation v2：

1.  从 react-navigation 中包括`createDrawerNavigation`和`DrawerItems`以及我们想要作为部分渲染的组件（主页和配置）：

```jsx
  // Dependencies
  import React, { Component } from 'react';
  import { StyleSheet, View, ScrollView, Image } from 'react-
  native';

  // React Navigation
  import { createDrawerNavigator, DrawerItems } from 'react-
  navigation';

  // Components
  import Home from './sections/Home';
  import Configuration from './sections/Configuration';
```

文件：App.js

1.  在 CustomDrawerComponent 中，我们将渲染 Codejobs 标志和菜单（您可以根据需要进行修改）：

```jsx
 // Custom Drawer Component
 // Here we are displaying the menu options 
  // and customizing our drawer
  const CustomDrawerComponent = props => (
    <View style={styles.area}>
      <View style={styles.drawer}>
        <Image
          source={require('./assets/codejobs.jpeg')}
          style={styles.logo}>
        </Image>
      </View>

 <ScrollView>
        <DrawerItems {...props} />
 </ScrollView>
 </View>
  );
```

文件：App.js

1.  创建`AppDrawerNavigator`，指定我们要在菜单中显示的组件作为部分（主页和配置）。此外，我们需要传递`contentComponent`与之前创建的`CustomDrawerComponent`：

```jsx
 // The left Drawer navigation
 // The first object are the components that we want to display
 // in the Drawer Navigation.
  const AppDrawerNavigator = createDrawerNavigator({
    Home,
    Configuration
  },
  {
    contentComponent: CustomDrawerComponent
  });
```

文件：App.js

1.  创建 App 类并渲染`AppDrawerNavigator`组件：

```jsx
  class App extends Component {
    render() {
      return (
        <AppDrawerNavigator />
      );
    }
  }

  // Styles for left Drawer
  const styles = StyleSheet.create({
    area: {
      flex: 1
    },
    drawer: {
      height: 150,
      backgroundColor: 'white',
      alignItems: 'center',
      justifyContent:'center'
    },
    logo: {
      height: 120,
      width: 120,
      borderRadius: 60
    }
  });

  export default App;
```

文件：App.js

1.  创建部分组件；第一个是主页组件：

```jsx
  // Dependencies
  import React, { Component } from 'react';
  import { View, Text, Image, TouchableOpacity } from 'react-native';
  // Styles
  import styles from './SectionStyles';
  class Home extends Component {
    // Here we specify the icon we want to render
 // in the menu for this option
    static navigationOptions = {
      drawerIcon: () => (
        <Image
          style={styles.iconsItem}
          source={require('../assets/home.png')}
        />
      )
    }
    render() {
      return(
        <View style={styles.container}>
          {/* Hamburger menu */}
          <TouchableOpacity 
            onPress={() => this.props.navigation.openDrawer()} 
            style={styles.iconMenu}
          >
            <Image
              style={styles.menu}
              source={require('../assets/menu.png')}
            />
          </TouchableOpacity>

          {/* Here is the content of the component */}
          <Text style={styles.titleText}>I'm the home section</Text>
        </View>
      );
    }
  }
  export default Home;
```

文件：sections/Home.js

1.  这是配置部分组件：

```jsx
  // Dependencies
  import React, { Component } from 'react';
  import { View, Text, Image, TouchableOpacity } from 'react-native';

  // Styles
  import styles from './SectionStyles';

  class Configuration extends Component {
 // Here we specify the icon we want to render
 // in the menu for this option
    static navigationOptions = {
      drawerIcon: () => (
        <Image
          style={styles.iconsItem}
          source={require('../assets/config.png')}
        />
      )
    };

    render() {
      return(
        <View style={styles.container}>
          {/* Hamburger menu */}
          <TouchableOpacity 
            onPress={() => this.props.navigation.openDrawer()} 
            style={styles.iconMenu}
          >
            <Image
              style={styles.menu}
              source={require('../assets/menu.png')}
            />
          </TouchableOpacity>

          {/* Here is the content of the component */}
          <Text style={styles.titleText}>I'm the configuration 
          section</Text>
        </View>
      );
    }
  }

 export default Configuration;
```

文件：sections/Configuration.js

1.  您可能已经注意到我们在两个组件上使用了相同的样式，这就是为什么我为样式创建了一个单独的文件：

```jsx
  import { StyleSheet } from 'react-native';

 export default StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: '#fff',
      alignItems: 'center',
      justifyContent: 'center',
    },
    iconMenu: {
      position: 'absolute',
      left: 0,
      top: 5
    },
    titleText: {
      fontSize: 26,
      fontWeight: 'bold',
    },
    menu: {
      width: 80,
      height: 80,
    },
    iconsItem: {
      width: 25,
      height: 25
    }
  });
```

文件：sections/sectionStyles.js

1.  您可以在存储库（`Chapter14/Recipe3/ReactNavigation/assets`）中找到我们正在使用的资产。

# 它是如何工作的...

如果您一切都做对了，您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/a052dd30-f924-435f-a83b-638c45f25c04.png)

正在呈现的第一个组件是`Home`组件。如果您点击汉堡菜单，您会看到抽屉中有两个部分（`Home`和`Configuration`），它们各自的图标以及顶部的 Codejobs 标志：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/dcc0a03c-da76-4ff7-8c97-6fe3a7c5ae85.png)

最后，如果您点击配置，您也会看到该组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/9f441f0e-0391-41b6-bc7a-e86a6c40dc2f.png)

如果您再次看到抽屉，您会注意到当前打开的部分也在菜单中处于活动状态（在这种情况下是配置）。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/71b34a74-dd57-455a-a21e-1f1688d78f3b.png)


# 第十五章：最常见的 React 面试问题

我想通过给你一些关于 React 和 JavaScript 在工作面试中最常见的问题来结束这本书：

+   React 问题：

+   React 是什么？它与其他 JS 库/框架有什么不同？

+   React 组件的生命周期中发生了什么？

+   你能告诉我关于 JSX 的一些信息吗？

+   真实 DOM 和虚拟 DOM 之间有什么区别？

+   React 有哪些限制？

+   解释 React 中`render()`的目的

+   在 React 中，状态是什么，如何使用它？

+   状态和属性之间有什么区别？

+   在 React 中，箭头函数是什么？如何使用它？

+   类组件和函数组件之间有什么区别？

+   无状态组件和纯组件之间有什么区别？

+   详细解释 React 组件的生命周期方法。

+   什么是高阶组件（HOC）？

+   Redux 是什么？

+   Flux 和 Redux 有什么不同？

+   在 React 中，ref 用于什么？

+   在 Redux 中，动作和减速器之间有什么区别？

+   如何提高 React 应用程序的性能？

+   JavaScript 问题：

+   回调和 Promise 之间有什么区别？

+   变量提升是什么？

+   apply 和 call 之间有什么区别？

+   什么是闭包，如何/为什么使用它？

+   事件委托是如何工作的？

+   冒泡和捕获之间有什么区别？

+   `bind()`是做什么的？

+   null、undefined 和未声明的变量之间有什么区别？

+   `==`和`===`之间有什么区别？

+   什么是“词法”作用域？

+   什么是函数式编程？

+   经典继承和原型继承之间有什么区别？
