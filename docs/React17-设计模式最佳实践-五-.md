# React17 设计模式最佳实践（五）

> 原文：[`zh.annas-archive.org/md5/49B07B9C9144903CED8C336E472F830F`](https://zh.annas-archive.org/md5/49B07B9C9144903CED8C336E472F830F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：部署到生产环境

现在您已经完成了您的第一个 React 应用程序，是时候学习如何将其部署到世界上了。为此，我们将使用名为**DigitalOcean**的云服务。

在本章中，您将学习如何在 DigitalOcean 的 Ubuntu 服务器上使用 Node.js 和 nginx 部署您的 React 应用程序。

在本章中，我们将涵盖以下主题：

+   创建一个 DigitalOcean Droplet 并对其进行配置

+   配置 nginx、PM2 和域名

+   实施 CircleCI 进行持续集成

# 技术要求

要完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

# 创建我们的第一个 DigitalOcean Droplet

我已经使用 DigitalOcean 六年了，我可以说这是我尝试过的最好的云服务之一，不仅因为价格实惠，而且配置起来非常简单快捷，社区也有很多更新的文档来解决与服务器配置相关的常见问题。

在这一点上，您需要投入一些资金来获得这项服务。我将向您展示最便宜的方法来做到这一点，如果将来您想增加 Droplets 的性能，您将能够在不重新配置的情况下增加容量。最基本的 Droplet 的最低价格是每月 5.00 美元（每小时 0.007 美元）。

我们将使用 Ubuntu 20.04（但也可以使用最新版本 21.04）；您将需要了解一些基本的 Linux 命令来配置您的 Droplet。如果您是 Linux 的初学者，不用担心，我会尽量以非常简单的方式向您展示每一步。

## 注册 DigitalOcean

如果您还没有 DigitalOcean 账户，可以在[`cloud.digitalocean.com/registrations/new`](https://cloud.digitalocean.com/registrations/new)注册。

您可以使用 Google 账户注册，也可以手动注册。一旦您使用 Google 注册，您将看到如下的账单信息视图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/3a701cc0-3c9a-4cc5-b304-4e518723cc42.png)

您可以使用信用卡支付，也可以使用 PayPal 支付。一旦您配置了付款信息，DigitalOcean 将要求您提供一些关于您的项目的信息，以便更快地配置您的 Droplet：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/5c0957de-f2de-41fc-988c-56f81847ff0d.png)

在接下来的部分，我们将创建我们的第一个 Droplet。

## 创建我们的第一个 Droplet

我们将从头开始创建一个新的 Droplet。按照以下步骤操作：

1.  选择“New Droplet”选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/23ed5cba-50b3-4543-b43b-c28748a63f9b.png)

1.  选择 Ubuntu 20.04（LTS）x64，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/d876496c-e9fa-4f4e-add7-9cd4835d1c0f.png)

1.  然后，选择基本计划，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/f32ed3a4-0eca-4bc9-aa91-5d7195394c30.png)

1.  然后，您可以在付款计划选项中选择$5/月：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/af83dac7-4472-4cb8-880c-41bb235b2957.png)

1.  选择一个地区。在这种情况下，我们将选择旧金山地区：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/bd868940-2def-4a09-967c-5fd7631912ba.png)

1.  创建一个根密码，添加 Droplet 的名称，然后点击“Create Droplet”按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/247ea094-92a3-4cc7-9371-70c6265443c1.png)

1.  创建 Droplet 大约需要 30 秒。创建完成后，您将能够看到它：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/e3344cf7-d36f-4777-8d98-f67e0960ac9a.png)

1.  现在，在您的终端中，您可以使用以下命令访问 Droplet：

```jsx
ssh root@THE_DROPLET_IP
```

1.  第一次访问时会要求输入指纹，只需输入 Yes，然后需要输入密码（创建 Droplet 时定义的密码）。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/f96f42b3-0d0b-47a9-a8af-7df7765da8cd.png)

现在我们已经准备好安装 Node.js 了，我们将在下一节中进行介绍。

## 安装 Node.js

现在您已连接到 Droplet，让我们对其进行配置。首先，我们需要使用个人软件包存档安装最新版本的 Node.js。撰写本书时的当前 Node 版本为 14.16.x。按照以下步骤安装 Node.js：

1.  如果在阅读本段时，Node 有新版本，请在`setup_14.x`命令中更改版本：

```jsx
cd ~
curl -sL https://deb.nodesource.com/setup_14.x -o nodesource_setup.sh
```

1.  一旦获得`nodesource_setup.sh`文件，运行以下命令：

```jsx
sudo bash nodesource_setup.sh 
```

1.  然后，通过运行以下命令安装 Node：

```jsx
sudo apt install nodejs -y
```

1.  如果一切正常，可以使用以下命令验证已安装的 Node 和`npm`的版本：

```jsx
node -v
v14.16.1
npm -v
6.14.12
```

如果您需要更新版本的 Node.js，您可以随时升级。

## 配置 Git 和 GitHub

我创建了一个特殊的存储库，以帮助您将第一个 React 应用程序部署到生产环境（[`github.com/D3vEducation/production`](https://github.com/D3vEducation/production)）。

在您的 Droplet 中，您需要克隆这个 Git 仓库（或者如果您的 React 应用程序已准备好部署，则使用您自己的仓库）。生产仓库是公开的，但通常您会使用私有仓库；在这种情况下，您需要将 Droplet 的 SSH 密钥添加到您的 GitHub 帐户中。要创建此密钥，请按照以下步骤操作：

1.  运行`ssh-keygen`命令，然后按*Enter*三次，不写任何密码：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/11f59ac8-2627-4f93-90ca-3209bb5a8967.png)如果您的终端闲置超过五分钟，您的 Droplet 连接可能会被关闭，您需要重新连接。

1.  创建 Droplet SSH 密钥后，您可以通过运行以下命令查看它：

```jsx
 vi /root/.ssh/id_rsa.pub
```

您会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/a33ffc30-07ae-4340-b1a0-00600326cf5d.png)

1.  复制您的 SSH 密钥，然后访问您的 GitHub 帐户。转到设置| SSH 和 GPG 密钥（[`github.com/settings/ssh/new`](https://github.com/settings/ssh/new)）。然后，在文本区域中粘贴您的密钥并为密钥添加标题：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/340744a9-2785-41c2-9e3e-7674574da84a.png)

1.  点击“添加 SSH 密钥”按钮后，您将看到您的 SSH 密钥，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/1202eee7-0bb8-4f61-8bef-0c7012d40205.png)

1.  现在您可以使用以下命令克隆我们的仓库（或您的仓库）：

```jsx
git clone git@github.com:FoggDev/production.git
```

1.  当您第一次克隆它时，您将收到一条消息，询问您是否允许 RSA 密钥指纹：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/e6195ece-4997-4645-838f-8e76c42afea9.png)

1.  你必须输入 yes 然后按*Enter*来克隆它：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/52f6974f-281b-45a6-b2d4-cc871ae52794.png)

1.  然后，您需要转到`production`目录并安装`npm`包：

```jsx
cd production
npm install
```

1.  如果要测试应用程序，只需运行`start`脚本：

```jsx
npm start
```

1.  然后打开浏览器，转到您的 Droplet IP 并添加端口号。在我的情况下，它是`http://144.126.222.17:3000`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/2a3fca3c-5bed-4679-9e76-c9c6aced2f83.png)

1.  这将以开发模式运行项目。如果要以生产模式运行，则使用以下命令：

```jsx
npm run start:production
```

你应该看到 PM2 正在运行，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/22418c84-00ae-4d2b-83b7-666ca37934fa.png)

1.  如果运行它并在 Chrome DevTools 的网络选项卡中查看，您将看到加载的捆绑包：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/605fd002-8001-4033-af1a-804659a0ce74.png)

我们现在的 React 应用程序在生产中运行，但让我们在下一节中看看我们可以用 DigitalOcean 做些什么。

## 关闭我们的 Droplet

要关闭 Droplet，请按照以下步骤操作：

1.  如果要关闭 Droplet，可以转到电源部分，或者可以使用开/关开关：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/19e7fb72-5d44-43b8-9549-217558c10baa.png)

1.  DigitalOcean 只有在您的 Droplet 处于开启状态时才会向您收费。如果单击开关以关闭它，那么您将收到以下确认消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/8a5da75d-431f-449d-9f96-442b034a2922.png)

通过这种方式，您可以控制您的 Droplet，并在不使用 Droplet 时避免不必要的支付。

# 配置 nginx，PM2 和域名

我们的 Droplet 已经准备好用于生产，但是正如你所看到的，我们仍然在使用端口`3000`。我们需要配置 nginx 并实现代理，将流量从端口`80`重定向到`3000`；这意味着我们将不再需要直接指定端口。**Node 生产进程管理器**（**PM2**）将帮助我们在生产环境中安全运行 Node 服务器。通常，如果我们直接使用`node`或`babel-node`命令运行 Node，并且应用程序出现错误，那么它将崩溃并停止工作。PM2 会在发生错误时重新启动节点服务器。

首先，在您的 Droplet 中，您需要全局安装 PM2：

```jsx
npm install -g pm2 
```

PM2 将帮助我们以非常简单的方式运行 React 应用程序。

## 安装和配置 nginx

要安装 nginx，您需要执行以下命令：

```jsx
sudo apt-get update
sudo apt-get install nginx
```

安装 nginx 后，您可以开始配置：

1.  我们需要调整防火墙以允许端口`80`的流量。要列出可用的应用程序配置，您需要运行以下命令：

```jsx
sudo ufw app list
Available applications:
 Nginx Full
 Nginx HTTP
 Nginx HTTPS
 OpenSSH
```

1.  `Nginx Full`表示它将允许从端口`80`（HTTP）和端口`443`（HTTPS）的流量。我们还没有配置任何带 SSL 的域名，所以现在我们应该限制流量只能通过端口`80`（HTTP）发送：

```jsx
sudo ufw allow 'Nginx HTTP'
Rules updated
Rules updated (v6) 
```

如果尝试访问 Droplet IP，您应该看到 nginx 正在工作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/b39df5db-2e1e-4114-8e43-236b111de353.png)

1.  您可以使用以下命令管理 nginx 进程：

```jsx
Start server: sudo systemctl start nginx
Stop server: sudo systemctl stop nginx 
Restart server: sudo systemctl restart nginx
```

Nginx 是一个非常流行的出色的 Web 服务器。

## 设置反向代理服务器

如我之前提到的，我们需要设置一个反向代理服务器，将流量从端口`80`（HTTP）发送到端口`3000`（React 应用程序）。为此，您需要打开以下文件：

```jsx
sudo vi /etc/nginx/sites-available/default 
```

步骤如下：

1.  在`location /`块中，您需要用以下内容替换文件中的代码：

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

1.  保存文件后，您可以使用以下命令验证 nginx 配置中是否存在语法错误：

```jsx
sudo nginx -t
```

1.  如果一切正常，那么您应该看到这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/cf501d03-f82e-4f54-96a3-350b4ad890d2.png)

1.  最后，您需要重新启动 nginx 服务器：

```jsx
sudo systemctl restart nginx
```

现在，您应该能够访问 React 应用程序而不需要端口，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/38c093cc-6348-4f20-94e7-8ef627e42167.png)

我们快要完成了！在下一节中，我们将向我们的 Droplet 添加一个域名。

## 将域名添加到我们的 Droplet

使用 IP 访问网站并不好；我们总是需要使用域名来帮助用户更容易地找到我们的网站。如果您想在 Droplet 上使用域名，您需要将您的域名的域名服务器更改为指向 DigitalOcean DNS。我通常使用 GoDaddy 来注册我的域名。要使用 GoDaddy 这样做，请按照以下步骤：

1.  转到[`dcc.godaddy.com/manage/YOURDOMAIN.COM/dns`](https://dcc.godaddy.com/manage/YOURDOMAIN.COM/dns)，然后转到 Nameservers 部分：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/d6917cb5-d6ac-4ddb-9be8-3ccabcc28434.png)

1.  单击“更改”按钮，选择“自定义”，然后指定 DigitalOcean DNS：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/1e25a5e2-3967-4e91-afa2-bacb9dcd64f8.png)

1.  通常，DNS 更改需要 15 到 30 分钟才能反映出来；现在，在更新了您的 Nameservers 之后，转到您的 Droplet 仪表板，然后选择添加域选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/342701e6-082f-4677-9632-325b4e2f9b0f.png)

1.  然后，输入您的域名，选择您的 Droplet，然后单击“添加域”按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/9e1c16fa-9600-4a70-a6ff-3a651985a4f8.png)

1.  现在，您需要为 CNAME 创建一个新记录。选择 CNAME 选项卡，在 HOSTNAME 中写入`www`；在别名字段中写入`@`；默认情况下，TTL 为`43200`。所有这些都是为了使用`www`前缀访问您的域名：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/606a3454-71e7-4845-8a21-66bd34cb270e.png)

如果你做的一切正确，你应该能够访问你的域名并看到 React 应用程序在运行。正如我之前所说，这个过程可能需要长达 30 分钟，但在某些情况下，可能需要长达 24 小时，这取决于 DNS 传播速度：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/caa2b2a8-3d7c-4920-a0d2-47451bd8e9b8.png)

太棒了，现在您已经正式将您的第一个 React 应用程序部署到生产环境！

# 实施 CircleCI 进行持续集成

我已经使用 CircleCI 有一段时间了，我可以告诉你，这是最好的 CI 解决方案之一：个人使用免费，无限的仓库和用户；每月有 1,000 分钟的构建时间，一个容器和一个并发作业；如果你需要更多，你可以升级计划，初始价格为每月 50 美元。

你需要做的第一件事是使用你的 GitHub 账户（或者如果你喜欢的话，Bitbucket）在网站上注册。如果你选择使用 GitHub，你需要在你的账户中授权 CircleCI，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/17413dc6-0528-4daf-a49f-1eef6fc00e92.png)

在下一节中，我们将向 CircleCI 添加我们的 SSH 密钥。

## 向 CircleCI 添加 SSH 密钥

现在你已经创建了你的账户，CircleCI 需要一种方式来登录到你的 DigitalOcean Droplet 来运行部署脚本。按照以下步骤完成这个任务：

1.  使用以下命令在 Droplet 内创建一个新的 SSH 密钥：

```jsx
ssh-keygen -t rsa
# Then save the key as /root/.ssh/id_rsa_droplet with no password.
# After go to .ssh directory
cd /root/.ssh
```

1.  之后，让我们将密钥添加到我们的`authorized_keys`中：

```jsx
cat id_rsa_droplet.pub >> authorized_keys
```

1.  现在，你需要下载私钥。为了验证你是否可以使用新密钥登录，你需要将其复制到你的本地机器，如下所示：

```jsx
# In your local machine do:
scp root@YOUR_DROPLET_IP:/root/.ssh/id_rsa_droplet ~/.ssh/
cd .ssh
ssh-add id_rsa_droplet
ssh -v root@YOUR_DROPLET_IP
```

如果你做的一切正确，你应该能够无需密码登录到你的 Droplet，这意味着 CircleCI 也可以访问我们的 Droplet：

1.  复制你的`id_rsa_droplet.pub`密钥的内容，然后转到你的仓库设置（[`app.circleci.com/settings/project/github/YOUR_GITHUB_USER/YOUR_REPOSITORY`](https://app.circleci.com/settings/project/github/YOUR_GITHUB_USER/YOUR_REPOSITORY)）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/93c72cb3-e3b7-41c5-9460-458519ca9425.png)

1.  前往 SSH 密钥，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/310a2714-d85f-4ae9-bd3d-b950cf2590e5.png)

1.  你也可以访问 URL [`app.circleci.com/settings/project/github/YOUR_GITHUB_USER/YOUR_REPOSITORY/shh`](https://app.circleci.com/settings/project/github/YOUR_GITHUB_USER/YOUR_REPOSITORY/shh)，然后在底部点击添加 SSH 密钥按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/961b1c0e-edbe-4e1d-8564-40ad8eb0ed79.png)

1.  粘贴你的私钥，然后为主机名字段提供一个名称；我们将其命名为`DigitalOcean`。

现在让我们在下一节中配置我们的 CircleCI 实例。

## 配置 CircleCI

现在你已经为 CircleCI 配置了对 Droplet 的访问权限，你需要向你的项目添加一个`config`文件，以指定你想要执行的部署过程中的作业。这个过程如下所示：

1.  为此，您需要创建`.circleci`目录，并在`config.yml`文件中添加以下内容：

```jsx
version: 2.1
jobs:
  build:
    working_directory: ~/tmp
    docker:
      - image: cimg/node:14.16.1
    steps:
      - checkout
      - run: npm install
      - run: npm run lint
      - run: npm test
      - run: ssh -o StrictHostKeyChecking=no $DROPLET_USER@$DROPLET_IP 'cd production; git checkout master; git pull; npm install; npm run start:production;'
workflows:
  build-deploy:
    jobs:
      - build:
        filters:
          branches:
            only: master
```

1.  当您有一个`.yml`文件时，您需要小心缩进；它类似于 Python，如果您没有正确使用缩进，将会出现错误。让我们看看这个文件的结构。

1.  指定我们将使用的 CircleCI 版本。在这种情况下，您正在使用版本`2.1`（在撰写本书时的最新版本）：

```jsx
version: 2.1
```

1.  在`jobs`内部，我们将指定它需要配置容器；我们将使用 Docker 创建它，并概述部署过程的步骤。

1.  `working_directory`将是我们用来安装 npm 包和运行部署脚本的临时目录。在这种情况下，我决定使用`tmp`目录，如下所示：

```jsx
jobs:
  build:
    working_directory: ~/tmp
```

1.  如我之前所说，我们将创建一个 Docker 容器，在这种情况下，我选择了一个包含`node: 14.16.1`的现有镜像。如果您想了解所有可用的镜像，您可以访问[`circleci.com/docs/2.0/circleci-images`](https://circleci.com/docs/2.0/circleci-images)：

```jsx
docker:
  - image: cimg/node:14.16.1
```

1.  对于代码情况，首先执行`git checkout`到`master`，然后在每个运行句子中，您需要指定要运行的脚本：

```jsx
steps:
  - checkout
  - run: npm install
  - run: npm run lint
  - run: npm test
  - run: ssh -o StrictHostKeyChecking=no $DROPLET_USER@$DROPLET_IP 'cd production; git checkout master; git pull; npm install; npm run start:production;'
```

按照以下步骤进行：

1.  首先，您需要使用`npm install`安装 npm 包，以便执行下一个任务。

1.  使用`npm run lint`执行 ESLint 验证。如果失败，它将中断部署过程，否则将继续下一次运行。

1.  使用`npm run test`执行 Jest 验证；如果失败，它将中断部署过程，否则将继续下一次运行。

1.  在最后一步中，我们连接到我们的 DigitalOcean Droplet，传递`StrictHostKeyChecking=no`标志以禁用严格的主机密钥检查。然后，我们使用`$DROPLET_USER`和`$DROPLET_IP` ENV 变量连接到它（我们将在下一步中创建它们），最后，我们将使用单引号指定我们将在 Droplet 内执行的所有命令。这些命令如下所示：

`cd production`：授予对生产环境（或您的 Git 存储库名称）的访问权限。

`git checkout master`：这将检出主分支。

`git pull`：从我们的存储库拉取最新更改。

`npm run start:production`：这是最后一步，它以生产模式运行我们的项目。

最后，让我们向 CircleCI 添加一些环境变量。

## 在 CircleCI 中创建 ENV 变量

如您之前所见，我们正在使用`$DROPLET_USER`和`$DROPLET_IP`变量，但是我们如何定义这些变量呢？请按照以下步骤进行：

1.  您需要再次转到项目设置，并选择环境变量选项。然后，您需要创建`DROPLET_USER`变量：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/535d47b9-6df3-4449-848a-db2d1f3371f2.png)

1.  然后，您需要使用您的 Droplet IP 创建`DROPLET_IP`变量：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/5870c9b9-5be2-4de3-b5ed-49dbacfba1df.png)

1.  现在，您需要将`config`文件推送到您的存储库，然后您就可以开始使用了。现在 CircleCI 已连接到您的存储库，每当您将更改推送到主分支时，它都会触发一个构建。

通常，前两个或三个构建可能会因为语法错误、配置中的缩进错误，或者因为我们有 linter 错误或单元测试错误而失败。如果失败，您将看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/50f0c757-8068-4422-bcef-a481af65d989.png)

1.  如您从上述截图中所见，第一个构建在底部失败，显示构建错误，第二个构建显示工作流构建-部署。这基本上意味着在第一个构建中，`config.yml`文件中有语法错误。

1.  在您修复`config.yml`文件中的所有语法错误和 linter 或单元测试的所有问题后，您应该看到一个成功的构建，就像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/eee20f66-2bae-4aab-aff8-88210f38dd7b.png)

1.  如果您点击构建编号，您可以看到 CircleCI 在发布 Droplet 的新更改之前执行的所有步骤：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/4b667573-7ef7-465d-a428-277e3c21e3fd.png)

1.  如您所见，步骤的顺序与我们在`config.yml`文件中指定的顺序相同；您甚至可以通过点击每个步骤来查看每个步骤的输出：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/c9005154-c317-41d9-8d36-dcc79f194f17.png)

1.  现在，假设您的 linter 验证或某些单元测试出现错误。在这种情况下，让我们看看会发生什么，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/c838d653-5b30-42dd-a1dc-e68417b2be39.png)

如您所见，一旦检测到错误，它将以代码`1`退出。这意味着它将中止部署并将其标记为失败，如您所见，在`npm run lint`之后的步骤都没有执行。

另一个很酷的事情是，如果您现在转到 GitHub 存储库并检查您的提交，您将看到所有成功构建的提交和所有失败构建的提交。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/8d591173-866f-43f5-bf29-3f230fc13dbd.png)

这太棒了-现在你的项目已经配置好自动部署，并且连接到你的 GitHub 仓库。

# 总结

我们的部署过程之旅已经结束，现在你知道如何将你的 React 应用部署到世界（生产环境），以及如何实现 CircleCI 进行持续集成。

在下一章中，我们将学习如何发布`npm`包。


# 第十五章：下一步

React 是过去几年中发布的最令人惊奇的库之一，不仅因为库本身及其出色的功能，更重要的是由于围绕它构建的生态系统。

跟随 React 社区是非常令人兴奋和鼓舞的；每一天都有新的项目和工具可以学习和玩耍。不仅如此，还有会议和聚会，您可以在现实生活中与人交谈并建立新的关系，可以阅读博客文章来提高技能和学习更多知识，以及许多其他方法来成为更好的开发人员。

React 生态系统鼓励最佳实践和对开源开发者的热爱，这对我们职业生涯的未来非常棒。

在本章中，我们将涵盖以下主题：

+   如何通过提出问题和拉取请求来为 React 库做出贡献

+   为什么重要回馈社区并分享您的代码

+   如何发布一个`npm`包以及如何使用语义版本控制

# 技术要求

要完成本章，您将需要以下内容：

+   Node.js 12+

+   Visual Studio Code

# 为 React 做出贡献

人们在使用 React 一段时间后经常想做的一件事情是为库做出贡献。React 是开源的，这意味着它的源代码是公开的，任何签署了**贡献者许可协议**（CLA）的人都可以帮助修复错误，编写文档，甚至添加新功能。

您可以在以下网址阅读完整的 CLA 条款：[`code.facebook.com/cla`](https://code.facebook.com/cla)。

您需要确保您在 React 的 GitHub 存储库中发布的任何错误是 100%可复制的。一旦您验证了这一点，并且如果您想在 GitHub 上提交问题，您可以转到[https](https://github.com/facebook/react/issues/new)[://github.com/facebook/react/issues/new](https://github.com/facebook/react/issues/new)。正如您将看到的，该问题附带了一些预填的说明，其中之一是设置最小演示。其他问题帮助您解释问题并描述当前和预期行为。

在参与或贡献到存储库之前，你需要阅读*Facebook 行为准则*，网址为[`code.facebook.com/codeofconduct`](https://code.facebook.com/codeofconduct)。该文件列出了所有社区成员期望的良好行为，每个人都应该遵循。问题提交后，你需要等待核心贡献者之一来检查并告诉你他们决定如何处理这个 bug。根据 bug 的严重程度，他们可能会修复它，或者要求你修复它。

在第二种情况下，你可以 fork 存储库并编写代码来解决问题。重要的是要遵循编码风格指南，并为修复编写所有测试。同样重要的是，所有旧测试都通过，以确保新代码不会在代码库中引入退化。当修复准备就绪并且所有测试都通过时，你可以提交一个拉取请求，并等待核心团队成员审查。他们可能决定合并它，或者要求你做一些更改。

如果你没有找到 bug，但仍然想为项目做贡献，你可以查看 GitHub 上标记为 good first issue 的问题：[`github.com/facebook/react/labels/good%20first%20issue`](https://github.com/facebook/react/labels/good%20first%20issue)。这是开始贡献的好方法，很棒的是 React 团队给了每个人，特别是新贡献者，成为项目的一部分的可能性。

如果你找到一个好的第一个 bug 问题，而且还没有被其他人占用，你可以在问题上添加评论，表示你有兴趣去解决它。核心成员之一会与你联系。在开始编码之前，一定要与他们讨论你的方法和路径，这样你就不必多次重写代码了。

改进 React 的另一种方式是添加新功能。重要的是要说 React 团队有一个计划要遵循，主要功能是由核心成员设计和决定的。

如果你对库接下来的步骤感兴趣，你可以在 GitHub 上的 Type: Big Picture 标签下找到其中一些：[`github.com/facebook/react/labels/Type%3A%20Big%20Picture`](https://github.com/facebook/react/labels/Type%3A%20Big%20Picture)。

也就是说，如果你有一些关于应该添加到库中的功能的好主意，首先要做的是提出一个问题并开始与 React 团队交谈。在向他们提问之前，你应该避免花时间编写代码并提交拉取请求，因为你心中的功能可能不符合他们的计划，或者可能与他们正在开发的其他功能产生冲突。

# 分发你的代码

为 React 生态系统做出贡献不仅意味着将代码推送到 React 存储库中。为了回馈社区并帮助开发人员，你可以创建软件包，撰写博客文章，回答 Stack Overflow 上的问题，以及执行许多其他活动。

例如，假设你创建了一个解决复杂问题的 React 组件，并且你认为其他开发人员使用它会比花时间构建他们自己的解决方案更有益。最好的做法是将其发布到 GitHub，并使其可供所有人阅读和使用。然而，将代码推送到 GitHub 只是一个大过程中的一个小动作，并且伴随着一些责任。因此，你应该对你的选择背后的原因有一个清晰的想法。

你想要分享你的代码的动机有助于提高你作为开发人员的技能。一方面，分享你的代码迫使你遵循最佳实践并编写更好的代码。另一方面，它使你的代码暴露于其他开发人员的反馈和评论之中。这是一个很好的机会，让你接收建议并改进你的代码，使其更好。

除了与代码本身相关的建议之外，将代码推送到 GitHub，你可以从其他人的想法中受益。事实上，你可能已经考虑过你的组件可以解决一个问题，但另一个开发人员可能会以稍微不同的方式使用它，为其找到新的解决方案。此外，他们可能需要新功能，他们可以帮助你实现这些功能，以便每个人，包括你自己，都能从中受益。共同构建软件是提高自己技能和软件包的一个很好的方式，这就是为什么我坚信开源的原因。

开源还能给你带来的另一个重要机会是让你与来自世界各地的聪明和热情的开发人员联系在一起。与具有不同背景和技能的新人密切合作是保持开放思维和提高自身能力的最佳途径之一。

共享代码也会给您带来一些责任，并且可能会耗费时间。事实上，一旦代码是公开的，人们可以使用它，您就必须对其进行维护。

维护存储库需要承诺，因为它变得越来越受欢迎，越来越多的人使用，问题和疑问的数量就会越来越多。例如，开发人员可能会遇到错误并提出问题，因此您必须浏览所有这些并尝试重现问题。如果问题存在，那么您必须编写修复程序并发布库的新版本。您可能会收到其他开发人员的拉取请求，这可能会很长，很复杂，需要进行审核。

如果您决定邀请其他人共同维护项目，并帮助您处理问题和拉取请求，您必须与他们协调，分享您的愿景并共同做出决策。

## 在推送开源代码时了解最佳实践

我们可以介绍一些好的实践，可以帮助您创建更好的存储库，并避免一些常见的陷阱。

首先，如果您想发布您的 React 组件，您必须编写一套全面的测试。对于公共代码和许多人的贡献，测试在许多方面都非常有帮助：

+   他们使得代码更加健壮。

+   他们帮助其他开发人员理解代码的功能。

+   他们使得在添加新代码时更容易找到回归。

+   他们使其他贡献者更有信心编写代码。

第二件重要的事情是添加一个带有组件描述、使用示例和可用的 API 和 props 文档的`README`。这有助于包的用户，但也避免了人们提出关于库如何工作以及如何使用它的问题。

还必须向存储库添加一个`LICENSE`文件，以使人们了解他们可以做什么，以及不能做什么。GitHub 有很多现成的模板可供选择。在您能做到的情况下，您应该保持包的体积小，并尽量减少依赖。当开发人员必须决定是否使用库时，他们往往会仔细考虑大小。请记住，庞大的包对性能有不良影响。

不仅如此，过多地依赖第三方库可能会在其中任何一个未得到维护或存在错误时造成问题。

在共享 React 组件时，一个棘手的部分是决定样式。共享 JavaScript 代码非常简单，而附加 CSS 并不像您想象的那么容易。事实上，您可以采取许多不同的路径来提供它：从向包中添加 CSS 文件到使用内联样式。要牢记的重要一点是 CSS 是全局的，通用的类名可能会与导入组件的项目中已经存在的类名发生冲突。

最好的选择是包含尽可能少的样式，并使组件对最终用户高度可配置。这样，开发人员更有可能使用它，因为它可以适应其自定义解决方案。

为了展示您的组件是高度可定制的，您可以向存储库添加一个或多个示例，以便让每个人都能轻松理解它的工作原理和接受哪些属性。示例也很有用，这样您就可以测试组件的新版本，并查看是否存在意外的破坏性更改。

正如我们在*第三章*，*React Hooks*中看到的，诸如**React Storybook**之类的工具可以帮助您创建生动的样式指南，这样您就更容易维护，包的使用者也更容易导航和使用。

一个非常好的例子是使用 Storybook 展示所有这些变化的高度可定制库是来自 Airbnb 的`react-dates`。您应该将该存储库视为如何将 React 组件发布到 GitHub 的完美示例。

正如您所看到的，他们使用 Storybook 来展示组件的不同选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react17-dsn-ptn-best-prac/img/9cc2adde-e6fb-4d18-9ab2-072773653d20.png)

最后但同样重要的是，您可能不仅想分享您的代码 - 您可能还想分发您的包。JavaScript 最流行的包管理器是`npm`，我们在本书中一直使用它来安装包和依赖项。

在下一节中，我们将看到使用`npm`发布新包是多么容易。

除了`npm`之外，一些开发人员可能需要将您的组件作为全局依赖项添加并在没有包管理器的情况下使用它。

正如我们在*第一章*，*开始使用 React*中看到的，您可以通过添加一个指向[`unpkg.com/`](https://unpkg.com/)的脚本标签来轻松使用 React。给您的库的用户提供相同的选择是很重要的。

因此，为了提供包的全局版本，您还应该构建**通用模块定义**（**UMD**）版本。使用 webpack，这非常简单；您只需在配置文件的输出部分设置`libraryTarget`。

# 发布 npm 包

将包发布给开发者最流行的方式是通过将其发布到`npm`，这是 Node.js 的包管理器。

我们在本书的所有示例中都使用了它，您已经看到安装包有多么容易；只需运行`npm install`包，就可以了。您可能不知道的是发布包也同样容易。

首先，假设您进入一个空目录，并在终端中输入以下内容：

```jsx
npm init
```

将创建一个新的`package.json`文件，并显示一些问题。第一个是包名称，默认为文件夹名称，然后是版本号。这些是最重要的，因为第一个是您的包的用户在安装和使用时将引用的名称；第二个帮助您安全地发布新版本的包，而不会破坏其他人的代码。

版本号由三个由点分隔的数字组成，它们都有意义。右侧包的最后一个数字代表补丁，当推送修复 bug 的新版本库时，应该增加这个数字。

中间的数字表示发布的次要版本，并且当向库添加新功能时应该更改。这些新功能不应该破坏现有的 API。最后，左侧的第一个数字代表主要版本，当发布包含破坏性更改的版本时，它必须增加。

遵循这种称为**语义化版本控制**（**SemVer**）的方法是一个良好的实践，它会让您的用户更加自信，因为他们需要更新您的包时会更加放心。

包的第一个版本通常是`0.1.0`。

要发布一个`npm`包，您必须拥有一个`npm`账户，您可以通过在控制台中运行以下命令轻松创建，其中`$username`是您选择的名称：

```jsx
npm adduser $username
```

用户创建后，您可以运行以下命令：

```jsx
npm publish
```

新条目将被添加到注册表中，其中包含您在`package.json`中指定的包名称和版本。

每当您在库中更改内容并且想要推送新版本时，您只需运行`$type`，其中一个补丁是次要的或主要的：

```jsx
npm version $type
```

该命令将自动在您的`package.json`文件中提升版本，并且如果您的文件夹处于版本控制下，它还将创建一个提交和一个标签。

一旦版本号增加，您只需再次运行`npm publish`，新版本将可供用户使用。

# 摘要

在这次环绕 React 世界的旅程的最后一站，我们看到了使 React 变得伟大的一些方面 - 其社区和生态系统 - 以及如何为它们做出贡献。

您学会了如何在发现 React 中的错误时提出问题，以及采取的步骤使其核心开发人员更容易修复它。您现在知道在开源代码时的最佳实践，以及随之而来的好处和责任。

最后，您看到了在`npm`注册表上发布软件包有多么容易，以及如何选择正确的版本号以避免破坏其他人的代码。
