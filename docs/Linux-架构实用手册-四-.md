# Linux 架构实用手册（四）

> 原文：[`zh.annas-archive.org/md5/7D24F1F94933063822D38A8D8705DDE3`](https://zh.annas-archive.org/md5/7D24F1F94933063822D38A8D8705DDE3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：变得更加熟悉 Salt

在经过**Salt**的基本概念后，我们最终将在本章中开始实践 Salt。我们将有机会在真实情景下工作，并为潜在客户设计和安装概念验证基础设施。我们将做一些如下的事情：

+   通过 Terraform 配置云基础设施

+   安装和配置 Salt 主服务器

+   安装和配置 minions

+   为 minions 创建状态和公式

+   通过 Salt 配置负载均衡器

执行这些任务后，您应该具备基本知识和实践经验，可以开始更深入地学习 Salt。

# 使用 Salt 进行实践

我们已经了解了 Salt 的不同组件和软件的功能，以及它如何帮助我们控制我们的基础设施。但我们还没有使用任何组件来实际维护任何系统，甚至安装 Salt。因此，让我们开始使用 Salt，并开始利用我们新获得的知识。 

在开始之前，我们将设置一个情景，以便更清楚地了解本章中我们将要做的事情，它将与一个真实情景相关。

# 情景

您已被 Don High 先生聘用，为他的公司设计系统管理平台。他希望在 Azure **虚拟机**（**VMs**）上运行他的 Web 服务器工作负载，采用**基础设施即服务**（**IaaS**）模型。

他的设置非常简单：他希望有两台虚拟机运行一个用`Node.js`编写的网站，位于 nginx 负载均衡器前面，将流量路由到网站的虚拟机中。他的所有基础设施都必须通过配置管理解决方案进行管理，以便每次他们提供新的虚拟机时，应用程序都会加载，并且可能需要运行其网站所需的任何配置。

他还告诉你的另一件事是，公司的员工在 Azure 中没有部署任何资源，并且他们希望看到**基础设施即代码**（**IaC**）如何在云中部署，以便他们的开发人员将来能够使用它。

# 构建我们的初始基础设施

我们在上一章中提到了**Terraform**，并且我们希望利用我们的客户要求我们通过 IaC 软件部署他的基础设施的事实，所以这是使用这个伟大工具的绝佳机会。

在执行每一步之前，我们将简要解释每一步，但如果您想了解更多，我们将在*进一步阅读*部分建议更多关于 Terraform 的深入讨论的书籍。

# 设置 Terraform

我们假设您将从类 Unix 工作站执行以下步骤。安装 Terraform 非常简单。Terraform 只是一个可以从`terraform.io`网站下载的二进制文件。

[`www.terraform.io/downloads.html`](https://www.terraform.io/downloads.html)

在我的情况下，我将使用 macOS 终端安装 Terraform：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/feabe7e2-a66a-428a-931c-9ccbbdb755bb.png)

下载后，您可以继续并在路径的一部分解压缩二进制文件：

！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/5d5c9321-527e-4c2d-98d9-8bb819acce1b.png)

通过运行`terraform version`检查 Terraform 版本：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/9dab0bb8-1b00-4e36-b1ec-018bd71ee8cb.png)

安装了 Terraform 后，我们需要安装 Azure CLI 以配置访问客户的 Azure 订阅。您可以在我们的*安装 Kubernetes*章节中找到安装 Azure CLI 和设置订阅的步骤。

安装了 Azure CLI 并设置了默认帐户后，我们可以配置 Terraform 以使用适当的凭据，以便它能够部署基础设施。

首先，我们将创建一个目录来存储我们的 Terraform 文件：

```
dsala@NixMachine: ~ $ mkdir terrafiles
```

接下来，我们将通过 Azure CLI 创建一个服务主体 ID，该 ID 将用于验证 Terraform 与我们的订阅。

将此命令的输出中的订阅 ID 保存到`$SUB_ID`变量中：

```
dsala@NixMachine: ~ $ az account show --query "{subscriptionId:id}"

dsala@NixMachine: ~ $ SUB_ID=<subscription id>
```

现在，运行以下命令来创建服务主体：

```
dsala@NixMachine: ~ $ az ad sp create-for-rbac \
--role="Contributor" \
--scopes="/subscriptions/${SUB_ID}"
```

注意从上一个命令返回的`appId`、`password`和`tenant`的值。

现在，在`terrafiles`目录中，创建一个名为`terraform.tfvars`的文件。

这个文件很特殊，因为当我们执行 Terraform 时，Terraform 会自动加载默认情况下存在的任何具有这个名称的文件。

这个文件应包含以下信息：

```
subscription_id = "azure-subscription-id"
tenant_id = "tenant-from-service-principal"
client_id = "appId-from-service-principal"
client_secret = "password-from-service-principal"
```

当你准备好文件后，创建另一个名为`az_creds.tf`的文件，其中包含以下内容：

```
variable subscription_id {}
variable tenant_id {}
variable client_id {}
variable client_secret {}

provider "azurerm" {
 subscription_id = "${var.subscription_id}"
 tenant_id = "${var.tenant_id}"
 client_id = "${var.client_id}"
 client_secret = "${var.client_secret}"
}
```

这个文件将是我们的变量文件，并且它将把凭据变量加载到 Azure 资源管理器 Terraform 提供程序中。

# 创建 IaC

现在我们准备开始创建我们的 IaC 声明文件。Terraform 使用自己的语言称为**Hashicorp 配置语言**（**HCL**）。你可以在以下链接找到更多信息：[`www.terraform.io/docs/configuration/index.html`](https://www.terraform.io/docs/configuration/index.html)。

让我们开始定义我们的资源。创建一个名为`main.tf`的文件。这将是我们的主模块文件。一个模块是一组共享共同目标或属于同一应用程序的资源。

`main.tf`的名称是 Hashicorp 推荐的名称，Hashicorp 是 Terraform 开源项目的公司所有者，用于最小模块。

你可以在 Terraform 文档中了解更多关于模块的信息：[`www.terraform.io/docs/modules/index.html`](https://www.terraform.io/docs/modules/index.html)。

我们的文件应包含接下来我们将声明的所有资源。

这是将包含我们 Azure 资源的资源组：

```
resource "azurerm_resource_group" "salt" {
name     = "Salt"
location = "East US"
}
```

这是我们子网的虚拟网络：

```
resource "azurerm_virtual_network" "salt" {
name                = "saltnet"
address_space       = ["10.0.0.0/16"]
location            = "${azurerm_resource_group.salt.location}"
resource_group_name = "${azurerm_resource_group.salt.name}"
}
```

请注意，我们通过以下语法从先前的资源中获取值：

```
"resource_type.local_name.value".
```

这是我们 VM 的地址空间的子网(s)：

```
resource "azurerm_subnet" "salt" {
name                 = "saltsubnet"
resource_group_name  = "${azurerm_resource_group.salt.name}"
virtual_network_name = "${azurerm_virtual_network.salt.name}"
address_prefix       = "10.0.0.0/24"
}
```

在这里，我们只创建一个包含我们的主节点和 minions 的子网，但只要它们在 VNET 地址空间内，你可以随时创建单独的子网，以便主节点和 minions 进行网络隔离。

创建了虚拟网络和子网后，我们需要为虚拟机创建防火墙规则。Azure 中的防火墙称为**网络安全组**，我们将继续使用网络安全组提供程序来创建防火墙及其规则。

这是我们负载均衡器的网络安全组：

```
resource "azurerm_network_security_group" "saltlb" {
 name                = "lb-nsg"
 location            = "${azurerm_resource_group.salt.location}"
 resource_group_name = "${azurerm_resource_group.salt.name}"
}
```

以下是用于访问负载均衡器 VM 的网络安全组规则。

`https`的端口：

```
resource "azurerm_network_security_rule" "httpslb" {
 name = "https"
 priority = 100
 direction = "inbound"
 access = "Allow"
 protocol = "Tcp"
 source_port_range = "*"
 destination_port_range = "8443"
 source_address_prefix = "*"
 destination_address_prefix = "*"
 resource_group_name = "${azurerm_resource_group.salt.name}"
 network_security_group_name = "${azurerm_network_security_group.saltlb.name}"
}
```

`http`端口：

```
resource "azurerm_network_security_rule" "httplb" {
 name                        = "http"
 priority                    = 101
 direction                   = "inbound"
 access                      = "Allow"
 protocol                    = "Tcp"
 source_port_range           = "*"
 destination_port_range      = "8080"
 source_address_prefix       = "*"
 destination_address_prefix  = "*"
 resource_group_name         = "${azurerm_resource_group.salt.name}"
 network_security_group_name = "${azurerm_network_security_group.saltlb.name}"
}
```

`access`的 SSH 端口：

```
resource "azurerm_network_security_rule" "sshlb" {
 name                        = "sshlb"
 priority                    = 103 direction                   = "inbound"
 access                      = "Allow"
 protocol                    = "Tcp"
 source_port_range           = "*" destination_port_range = "22"
 source_address_prefix       = "*"
 destination_address_prefix  = "*"
 resource_group_name         = "${azurerm_resource_group.salt.name}"
 network_security_group_name = "${azurerm_network_security_group.saltlb.name}"
}
```

主 VM 的第二个网络安全组如下：

```
resource "azurerm_network_security_group" "saltMaster" {
 name                = "masternsg"
 location            = "${azurerm_resource_group.salt.location}"
 resource_group_name = "${azurerm_resource_group.salt.name}"
}
```

以下是主 VM 的网络安全组规则。

以下是 Salt 的`publisher`端口：

```
resource "azurerm_network_security_rule" "publisher" {
 name                        = "publisher"
 priority                    = 100
 direction                   = "inbound"
 access                      = "Allow"
 protocol                    = "Tcp"
 source_port_range           = "*"
 destination_port_range      = "4505"
 source_address_prefix       = "*"
 destination_address_prefix  = "*"
 resource_group_name         = "${azurerm_resource_group.salt.name}"
 network_security_group_name = "${azurerm_network_security_group.saltMaster.name}"
}
```

以下是 Salt 的请求服务器端口：

```
resource "azurerm_network_security_rule" "requestsrv" {
 name                        = "requestsrv"
 priority                    = 101
 direction                   = "inbound"
 access                      = "Allow"
 protocol                    = "Tcp"
 source_port_range           = "*"
 destination_port_range      = "4506"
 source_address_prefix       = "*"
 destination_address_prefix  = "*"
 resource_group_name         = "${azurerm_resource_group.salt.name}"
 network_security_group_name = "${azurerm_network_security_group.saltMaster.name}"
}
```

主机的`ssh`端口如下：

```
resource "azurerm_network_security_rule" "sshmaster" {
 name                        = "ssh"
 priority                    = 103
 direction                   = "inbound"
 access                      = "Allow"
 protocol                    = "Tcp"
 source_port_range           = "*"
 destination_port_range      = "22"
 source_address_prefix       = "*"
 destination_address_prefix  = "*"
 resource_group_name         = "${azurerm_resource_group.salt.name}"
 network_security_group_name = "${azurerm_network_security_group.saltMaster.name}"
}
```

minions 的网络安全组如下：

```
resource "azurerm_network_security_group" "saltMinions" {
 name                = "saltminions"
 location            = "${azurerm_resource_group.salt.location}"
 resource_group_name = "${azurerm_resource_group.salt.name}"
}
```

这个最后的网络安全组很特殊，因为我们不会为它创建任何规则。Azure 提供的默认规则只允许 VM 与 Azure 资源通信，这正是我们这些 VM 所希望的。

我们 Nginx 负载均衡器 VM 的公共 IP 地址如下：

```

resource "azurerm_public_ip" "saltnginxpip" {
 name                         = "lbpip"
 location                     = "${azurerm_resource_group.salt.location}"
 resource_group_name          = "${azurerm_resource_group.salt.name}"
 public_ip_address_allocation = "static"
}
```

我们负载均衡器的虚拟网络接口如下：

```
resource "azurerm_network_interface" "saltlb" {
 name                = "lbnic"
 location            = "${azurerm_resource_group.salt.location}"
 resource_group_name = "${azurerm_resource_group.salt.name}"
 network_security_group_id  = "${azurerm_network_security_group.saltlb.id}"

 ip_configuration {
 name                          = "lbip"
 subnet_id                     = "${azurerm_subnet.salt.id}"
 private_ip_address_allocation = "dynamic"
 public_ip_address_id          = "${azurerm_public_ip.saltnginxpip.id}"
 }
}
```

我们的 Web 服务器 VM 的虚拟网络接口如下：

```
resource "azurerm_network_interface" "saltminions" {
 count               = 2
 name                = "webnic${count.index}"
 location            = "${azurerm_resource_group.salt.location}"
 resource_group_name = "${azurerm_resource_group.salt.name}"
 network_security_group_id  = "${azurerm_network_security_group.saltMinions.id}"

 ip_configuration {
 name                          = "web${count.index}"
 subnet_id                     = "${azurerm_subnet.salt.id}"
 private_ip_address_allocation = "dynamic"
 }
}
```

以下是我们主 VM 的公共 IP 地址：

```
resource "azurerm_public_ip" "saltmasterpip" {
 name                    = "masterpip"
 location                = "${azurerm_resource_group.salt.location}"
 resource_group_name     = "${azurerm_resource_group.salt.name}"
 allocation_method       = "Dynamic"
}
```

这个公共 IP 地址将用于我们 SSH 到主 VM；这就是为什么我们要动态分配它。

主 VM 的虚拟网络接口如下：

```
resource "azurerm_network_interface" "saltmaster" {
 name                = "masternic"
 location            = "${azurerm_resource_group.salt.location}"
 resource_group_name = "${azurerm_resource_group.salt.name}"
 network_security_group_id     = "${azurerm_network_security_group.saltMaster.id}"

 ip_configuration {
 name                          = "masterip"
 subnet_id                     = "${azurerm_subnet.salt.id}"
 private_ip_address_allocation = "static"
 private_ip_address            = "10.0.0.10"
 public_ip_address_id          = "${azurerm_public_ip.saltmasterpip.id}"
 }
}
```

以下是 Web 服务器 VMs：

```
resource "azurerm_virtual_machine" "saltminions" {
count                 = 2
name                  = "web-0${count.index}"
location              = "${azurerm_resource_group.salt.location}"
resource_group_name   = "${azurerm_resource_group.salt.name}"
network_interface_ids = ["${element(azurerm_network_interface.saltminions.*.id, count.index)}"]
vm_size               = "Standard_B1s"
storage_image_reference {
 publisher = "Canonical"
 offer     = "UbuntuServer"
 sku       = "16.04-LTS"
 version   = "latest"
}
storage_os_disk {
 name              = "webosdisk${count.index}"
 caching           = "ReadWrite"
 create_option     = "FromImage"
 managed_disk_type = "Standard_LRS"
}
os_profile {
 computer_name  = "web-0${count.index}"
 admin_username = "dsala"
}
os_profile_linux_config {
 disable_password_authentication = true
 ssh_keys = {
 path   = "/home/dsala/.ssh/authorized_keys"
 key_data = "${file("~/.ssh/id_rsa.pub")}"
 }
 }
}
```

用你自己的信息替换`os_profile.admin_username`和`os_profile_linux_config.key_data`。

主 VM 如下：

```
resource "azurerm_virtual_machine" "saltmaster" {
name                  = "salt"
location              = "${azurerm_resource_group.salt.location}"
resource_group_name   = "${azurerm_resource_group.salt.name}"
network_interface_ids = ["${azurerm_network_interface.saltmaster.id}"]
vm_size               = "Standard_B1ms"

storage_image_reference {
 publisher = "OpenLogic"
 offer     = "CentOS"
 sku       = "7.5"
 version   = "latest"
}

storage_os_disk {
 name              = "saltos"
 caching           = "ReadWrite"
 create_option     = "FromImage"
 managed_disk_type = "Standard_LRS"
}

os_profile {
 computer_name  = "salt"
 admin_username = "dsala"
}

os_profile_linux_config {
 disable_password_authentication = true
 ssh_keys = {
 path   = "/home/dsala/.ssh/authorized_keys"
 key_data = "${file("~/.ssh/id_rsa.pub")}"
 }
 }
}
```

以下是 Nginx 负载均衡器 VM：

```
resource "azurerm_virtual_machine" "saltlb" {
name                  = "lb-vm"
location              = "${azurerm_resource_group.salt.location}"
resource_group_name   = "${azurerm_resource_group.salt.name}"
network_interface_ids = ["${azurerm_network_interface.saltlb.id}"]
vm_size               = "Standard_B1ms"

storage_image_reference {
 publisher = "OpenLogic"
 offer     = "CentOS"
 sku       = "7.5"
 version   = "latest"
}

storage_os_disk {
 name              = "lbos"
 caching           = "ReadWrite"
 create_option     = "FromImage"
 managed_disk_type = "Standard_LRS"
}

os_profile {
 computer_name  = "lb-vm"
 admin_username = "dsala"
}

os_profile_linux_config {
 disable_password_authentication = true
 ssh_keys = {
 path   = "/home/dsala/.ssh/authorized_keys"
 key_data = "${file("~/.ssh/id_rsa.pub")}"
 }
 }
}
```

保存了所有先前创建的资源的文件后，运行`terraform init`命令；这将使用 Terraform 文件初始化当前目录并下载 Azure Resource Manager 插件：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/93e5f877-3ccb-4d9a-8341-7c5856fe74e1.png)

如果您想了解更多关于`init`命令的信息，您可以访问[`www.terraform.io/docs/commands/init.html`](https://www.terraform.io/docs/commands/init.html)。

运行`init`命令后，我们将继续运行`terraform plan`命令，该命令将计算实现我们在`tf`文件中定义的所需状态的所有必要更改。

在运行`terraform apply`命令之前，这不会对现有基础设施进行任何更改：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/a8664294-dfb1-4dac-b50f-0e8b9ba6c0c4.png)

有关`plan`命令的更多信息，请访问[`www.terraform.io/docs/commands/plan.html`](https://www.terraform.io/docs/commands/plan.html)。

完成`plan`命令后，您可以继续运行`terraform apply`，然后会提示您确认应用更改：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/dc8b2af1-fd20-4c75-88fe-34fda9b02123.png)

完成后，您应该能够看到以下消息：

```
Apply complete! Resources: 18 added, 0 changed, 0 destroyed.
 Installing, Configuring and Managing Salt
```

安装 Salt 有两种方式：您可以使用引导脚本安装主服务器和 minions，也可以通过 Salt 存储库手动安装和配置它们。

我们将覆盖两种方式，以便熟悉安装过程。

# 使用软件包管理器安装 Salt

在我们当前的基础设施中，我们有一个主服务器和三个 minions。我们的主服务器和一个 minion 正在运行 CentOS 7.5，其余的 VM 都在 Ubuntu 16.04 上。在这两个发行版上，流程会有所不同，但在两者上有一些相同的步骤。

# 安装 CentOS yum

以前，Salt 只能通过 EPEL 存储库获得。但现在 SaltStack 有自己的存储库，我们可以从那里导入并执行安装。

首先，在主 VM 中安装 SSH，然后运行以下命令导入 SaltStack 存储库：

```
[dsala@salt ~]$ sudo yum install \
https://repo.saltstack.com/yum/redhat/salt-repo-latest.el7.noarch.rpm
```

可选的，您可以运行`yum clean expire-cache`，但由于这是一个新的虚拟机，这是不必要的。

完成后，我们将继续安装`salt-master`包：

```
[dsala@salt ~]$ sudo yum install salt-master -y
```

继续启用`systemd` salt-master 服务单元：

```
[dsala@salt ~]$ sudo systemctl enable salt-master --now
```

检查服务是否正在运行：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/e769658e-a6f2-4b19-bccb-a448ec47b6f6.png)

一旦服务正常运行，请通过运行以下命令检查 VM 的私有 IP 是否与我们在 Terraform 定义中配置的 IP 一致：

```
[dsala@salt ~]$ ifconfig eth0 | grep inet | head -1 | awk '{print $2}'
```

确认了 IP 地址后，打开另一个终端并 SSH 到负载均衡器 minion。重复在主 VM 中添加存储库的过程。

添加存储库后，运行以下命令安装`salt-minion`包：

```
[dsala@lb-vm ~]$ sudo yum install salt-minion -y
```

通过运行以下命令启用和启动`systemd`服务单元：

```
[dsala@lb-vm ~]$ sudo systemctl enable salt-minion --now
```

在我们对其进行任何更改之前，让我们检查服务是否成功启动：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/825d4968-b0ff-44e2-9a6a-1f48c0e6d3e8.png)

我们可以看到服务上出现错误，说主服务器已更改公钥，我们无法连接到 Salt 主服务器。现在我们需要配置 minion 与主服务器通信。但首先，让我们安装剩下的两个 Ubuntu minions，因为在两个发行版上注册 minions 的过程是相同的。

# Ubuntu apt-getting Salt

这唯一复杂的部分是，由于我们的 Web 服务器没有分配给它们的公共 IP 地址，您必须从主 VM 或负载均衡器 VM 对它们进行 SSH。为此，您可以从这两个 VM 中的任何一个设置 SSH 密钥认证到 minions。如果您正在阅读本书，您将熟悉如何执行此任务。

登录到 Web 服务器 VM 后，在两个 VM 中执行以下任务。

导入 Salt 存储库的`gpg`密钥：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/1e052271-d854-4803-bf72-0f1141732e2f.png)

运行以下命令创建存储库：

```
dsala@web-00:~$ echo "deb http://repo.saltstack.com/apt/ubuntu/16.04/amd64/latest xenial main" \
| sudo tee /etc/apt/sources.list.d/saltstack.list
```

添加了存储库后，运行`apt update`，您应该能够看到存储库已列出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/4b4b29ec-0fb9-492b-a738-586bd3599e16.png)

继续安装`salt-minion`软件包：

```
dsala@web-00:~$ sudo apt install salt-minion -y
```

通过运行以下命令启用并检查`salt-minion`服务的状态：

```
dsala@web-00:~$ sudo systemctl enable salt-minion --now && systemctl status salt-minion
```

您应该看到与 CentOS LB 虚拟机中看到的相同的消息。

# 通过引导脚本安装 Salt

通过**引导脚本**安装 Salt 的第二种方法。此脚本会自动检测我们的发行版并下载定义的软件包。该脚本还为我们提供了`-A`标志，该标志将主机的地址添加到我们的 minions 中。

要获取脚本，您可以使用`wget`或`curl`；官方 SaltStack 使用`curl`：

```
user@master:~$ curl -L https://bootstrap.saltstack.com -o install_salt.sh
```

此脚本适用于主机和 minions；运行脚本时使用的标志不同。

要安装主机组件，请使用`-M`标志运行脚本，用于主机和`-P`允许安装任何 Python `pip`软件包。我们还可以使用`-A`指定主机地址，并告诉脚本不要使用`-N`标志在主机中安装 minion 服务：

```
user@master:~$ sudo sh install_salt.sh -P -M
```

要安装 minion，只需运行此命令：

```
user@master:~$ sudo sh install_salt.sh -P -A <salt master IP>
```

# 主机和 minion 握手

在安装的这个阶段，我们将允许我们的 minions 与主机通信，验证它们的指纹，并设置配置文件。

首先，我们将 SSH 到主机 VM 并编辑主机的配置文件，告诉 salt-master 守护程序要绑定到哪个 IP。

编辑`/etc/salt/master`文件，查找`interface:`行，并添加主机的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/b4c6833d-9ee3-48ef-8875-5dac0eb854b1.png)

修改文件后，运行`daemon-reload`和`restart`命令，以便服务确认更改：

```
[dsala@salt ~]$ sudo systemctl daemon-reload && sudo systemctl restart  salt-master
```

您可以通过运行`ss`命令来验证 Salt 主机是否在正确的 IP 地址上监听：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/9204ea5f-fd29-400e-9658-997a74380305.png)

现在我们的主机正在监听我们需要的 IP 地址，是时候配置我们的 minions 了。

让我们开始修改 minion 的配置文件。请记住，这些步骤需要在所有 minions 上执行，而不管它们的发行版如何。

查找`/etc/salt/minion`文件，并通过在`master:`下添加主机的 IP 地址来编辑它。我们将找到一个已配置的值：`master: salt`*；*这是因为 Salt 默认情况下通过对主机名`salt`进行 DNS 查询来查找主机，但是因为我们打算在将来拥有多个主机，所以我们将使用我们主机 VM 的静态 IP 地址设置此文件：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/119ef727-6f47-4379-ab79-30e57a5d9790.png)

在我们的 minions 可以交换密钥之前，我们需要将主机的指纹添加到我们 minions 的配置文件中。

SSH 回到主机并运行以下命令以获取主机的公共指纹：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/2ad8c09e-e899-4e05-b0a0-1b694a2372d9.png)

复制`master.pub`的值，并返回编辑 minion 的配置文件。在 minion 的配置文件中，使用在前一步中获得的主机公钥编辑`master_finger: ' '`行：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/457bff79-3eda-4ead-afe0-3d8ea04b6c68.png)

完成最后一个任务后，重新加载并重新启动 minion 守护程序：

```
[dsala@web-00 ~]$ sudo systemctl daemon-reload && sudo systemctl restart salt-master
```

在退出每个 minion 之前，运行以下命令并注意 minion 的指纹：

```
[dsala@web-00 ~]$ sudo salt-call --local key.finger
```

一旦您注意到所有 minions 的指纹，请继续登录到主机。

在主机上，我们将比较主机看到的指纹与我们在每个 minion 本地看到的指纹。通过这种方式，我们将确定我们将接受的 minions 确实是我们的 minions。

要做到这一点，在主机上运行以下命令：`salt-key -F`。这将打印所有密钥，因此您不必逐个打印每个密钥：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/6cbc1bd3-57c7-419a-b01d-ade25cef3e1b.png)

确保密钥相同，然后我们将继续接受密钥。

在`salt-key -F`命令下，我们看到有未接受的密钥需要验证；我们将运行`salt-key -A`来接受所有待处理的密钥，然后可以运行`salt-key -L`来验证这些密钥是否被接受：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/9e63d0bb-c9b8-4324-abda-1dcf5aeab75f.png)

现在我们的 minion 已经经过身份验证，我们可以继续从 master 发出命令。

为了测试我们的 minion，我们将从测试模块调用`ping`函数：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/62c648ed-d9c6-4e8c-b3f5-7580aec2204d.png)

所有 minion 应该回应`True`，表示 Salt minion 守护程序正在响应，我们准备开始管理我们的基础设施。

# 使用 Salt 工作

我们的 SaltStack 已经运行起来了，我们准备开始为我们的虚拟机创建公式和定制配置。

# 创建 WebServer 公式

我们现在将创建必要的状态文件来创建安装和配置我们的 web 服务器的公式。

在开始之前，我们需要首先创建我们的状态树，其中将包含所有状态文件：

```
[dsala@salt ~]$ sudo mkdir /srv/salt
```

在这个目录中，我们将创建一个名为`top.sls`的文件。这个文件告诉 Salt 要应用哪些状态到哪些 minion 上。和 Salt 中的每个定义一样，`top.sls`是一个基于 YAML 的文件，其中包含要定位的 minion 和应用到这些 minion 的状态文件。

在`/srv/salt`目录中创建一个名为`top.sls`的文件，内容如下：

```
base:
    'web*':
       - webserver.nodejs
```

`base:`表示我们正在工作的环境；由于这是一个简单的环境，我们只需要基本环境；如果要处理多个环境，可以参考我们在*进一步阅读*部分建议的一本书。

接下来，我们有`web*`条目；这个条目告诉 Salt 要应用状态的 minion IDs。正如你所看到的，你可以使用 globbing 来定位 minion IDs。

最后，`- webserver.nodejs`是我们指示要应用的状态；`webserver`表示`nodejs.sls`文件所在的文件夹。由于 YAML 是由 Python 解释器读取的，我们需要用句点（.）而不是斜杠（/）来定义路径。最后一个词将是要加载的`.sls`文件的名称。

因为我们定义了`Node.js`文件在一个名为`webserver`的目录中，这个目录将存储我们所有的 web 服务器状态文件，我们需要创建这样一个目录：

```
[dsala@salt ~]$ sudo mkdir /srv/salt/webserver
```

现在我们有了存储状态定义的目录，让我们创建我们的第一个状态定义，安装`node.js`包和`npm`。在`/srv/salt/webserver/`目录中创建一个名为`nodejs.sls`的文件，内容如下：

```
nodejs:
    pkg.installed

npm:
    pkg.installed
```

`nodejs`字段是要安装的包，后面是要调用的`pkg.installed`函数。

创建了`state`文件后，将`state`文件应用到 web 服务器 minion 上：

```
[dsala@salt ~]$ sudo salt 'web*' state.apply
```

过一会儿，你将收到应用更改和持续时间的输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/c190431a-8901-4572-a771-31a159e753ce.png)

以下示例的输出已经被截断以提高可读性。

安装了 Node.JS 后，我们现在需要为 Node.JS 网站创建用户。

我们将创建另一个状态文件来定义用户配置。

在`/srv/salt/webserver/`目录下创建另一个名为`webuser.sls`的文件，内容如下声明：

```
webuser:
  user.present:
    - name: webuser
    - uid: 4000
    - home: /home/webuser
```

在执行状态之前，修改`top.sls`文件以反映新添加的状态文件：

```
base:
   'web*':
     - webserver.nodejs
     - webserver.webuser   
```

再次执行`salt '*' state.apply`命令，你应该会收到用户创建的输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/a4c327a2-dc6f-482c-b61c-fe50304b37be.png)

现在我们有了将运行网站的用户，是时候将网站文件复制到我们的网站服务器上了。为此，我们将创建另一个状态文件，使用 Git 下载网站文件并加载到 VM 中。

修改你的`top.sls`文件，并在同一个 web 服务器目录下添加另一个名为`gitfetch`的状态：

```
base:
   'web*':
     - webserver.nodejs
     - webserver.webuser
     - webserver.gitfetch
```

现在，继续使用`git.latest`函数创建`gitfetch.sls`文件，以从 Git 存储库下载代码并在每次下载存储库时安装`Node.js`依赖项：

```
node-app:
     git.latest:
       - name: https://github.com/dsalamancaMS/SaltChap.git
       - target: /home/webuser/app
       - user: webuser

dep-install:
     cmd.wait:
       - cwd: /home/webuser/app
       - runas: webuser
       - name: npm install
       - watch:
         - git: node-app
```

继续运行`state.apply`函数，以在两台 Web 服务器上下载应用程序。运行命令后，您应该能够看到类似于以下内容的输出：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/57ccb71f-cd5a-4e5f-a3e6-9ed585b01935.png)

有了我们的 Web 服务器中的代码，我们几乎完成了我们的 Ubuntu minions 的配置。

现在我们需要将我们的 Node.JS 应用程序作为守护程序运行。

为此，我们将使用 Supervisor 开源项目：[`github.com/Supervisor/supervisor`](https://github.com/Supervisor/supervisor)。

现在，让我们配置 Salt，使`Supervisor`监视我们的 Node.JS Web 应用程序。编辑`top.sls`文件，添加以下行，就像我们以前做过的那样：

```
- webserver.suppkg
```

在创建`supervisor`状态文件之前，我们首先需要创建要推送到我们 minions 的`supervisor`配置文件。在 Web 服务器目录中创建一个名为`supervisor.conf`的文件，内容如下：

```
[program:node-app]
command=nodejs .
directory=/home/webuser/app
user=webuser
```

现在创建`suppkg.sls`状态文件，负责管理之前的配置文件，在 Web 服务器文件夹下：

```
supervisor:
  pkg.installed:
    - only_upgrade: False
  service.running:
    - watch:
       - file: /etc/supervisor/conf.d/node-app.conf

/etc/supervisor/conf.d/node-app.conf:
 file.managed:
  - source: salt://webserver/supervisor.conf
```

创建文件后，继续运行`salt 'web*' state.apply`命令以应用最新状态。

应用了最后一个状态后，我们的 Web 应用程序应该已经启动运行。您可以尝试通过`curl`命令访问它：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/16008511-4326-40d9-93f0-2217fe0f0660.png)

现在我们的 Web 服务器已经准备好了，我们将对它们进行标记。还记得上一章我们谈到的 grains 吗。这就是我们接下来要做的事情。

让我们继续为我们的`web-00`和`web-01`服务器打上适当的角色标签。

要做到这一点，为每台服务器运行以下命令：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/972a54da-2dcc-4f31-8cb0-058bfe8cf641.png)

您可以通过运行以下`grep`来检查角色是否成功应用：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/1e6f0ed5-af0b-404a-9595-534b7ea5b304.png)

# 创建负载均衡公式

现在我们的两台 Web 服务器已经正确设置，我们可以配置我们的最后一个 minion。这个 minion 将运行 Nginx，以便在负载均衡器后面平衡和代理请求到我们的 Web 服务器。

让我们创建一个目录，我们将在其中存储我们的负载均衡器的所有状态：

```
[dsala@salt ~]$ sudo mkdir /srv/salt/nginxlb
```

创建目录后，让我们继续最后一次编辑我们的`top.sls`文件，以包括`负载均衡器`状态文件。`top.sls`文件应该如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/2bd3ae04-7f0a-4f1e-952e-e79ae6e34324.png)

在创建我们的`负载均衡器`状态文件之前，我们将创建要推送到我们`负载均衡器`VM 的 Nginx 配置文件。创建一个名为`nginx.conf`的文件，内容如下：

```
events { }
http {
 upstream webapp {
   server web-00:8080;
   server web-01:8080;
 }
 server {
   listen 8080;
   location / {
     proxy_pass http://webapp;
   }
 }
}
```

现在，让我们继续创建我们的最终状态文件。在`/srv/salt/`的`nginxlb`目录下创建一个名为`lb.sls`的文件，内容如下：

```
epel-release:
 pkg.installed

nginx:
 pkg.installed:
 - only_upgrade: False
 service.running:
 - watch:
    - file: /etc/nginx/nginx.conf

/etc/nginx/nginx.conf:
 file.managed:
  - source: salt://nginxlb/nginx.conf
```

应用最终更改，您可以运行`state.apply`命令。

完成后，您可以继续测试负载均衡器，运行 cURL 到其公共 IP 地址：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/0c17a1c2-32f2-43dd-8521-734d0f1fecc4.png)

通过这个最终配置，我们已经完成了对 Don High 先生的概念验证。一个非常重要的事实要注意的是，这个例子还远远没有准备好投入生产；这只是一个例子，展示了 Salt Stack 的基本功能和可能性。

# 总结

在本章中，我们最终通过 IaC 部署了 Salt，与 Salt 进行了互动。我们使用 Terraform 设置了我们的初始环境，并且要开始使用 Terraform，我们只需从`terraform.io`下载二进制文件。可以通过`terraform version`命令检查 Terraform 的版本。安装了 Terraform 后，我们获取了连接到我们的 Azure 订阅的正确详细信息，使用 AZ CLI。

一旦 Terraform 能够连接到 Azure，我们就开始创建 IaC 声明文件，其中包含了在 Azure 中正确部署我们想要的资源的必要信息，以我们想要的方式。

通过 Terraform 部署完成后，我们开始安装 Salt。这可以通过操作系统的软件包管理器（`yum`和`apt`）或引导脚本的两种不同方式来完成。

在通过软件包管理器安装时，我们需要添加 Salt 存储库，因为它在基本存储库中不可用；我们通过从`saltstack`网站下载`rpm`来完成这一点。

为了安装 master，我们运行了`sudo yum install salt-master`，为了安装 minions，我们运行了`sudo yum install salt-minion -y`。对于 Ubuntu，过程类似，只是使用了`apt`软件包管理器。

在 Salt 完成安装后，我们启用了`systemctl`单元。一旦 Salt 运行起来，我们需要允许 minions 与 master 通信；这是通过 SSH 指纹完成的。

在这一点上，Salt 正在运行，minions 正在与 master 通信，所以我们开始创建 web 服务器公式，运行必要的定义来部署应用程序。

在下一章中，本书的最后一章，我们将介绍设计解决方案时的一些最佳实践。


# 第十五章：设计最佳实践

总结这本书时，我们的最后一章将讨论你必须遵循的不同最佳实践，以设计一个具有弹性和防故障的解决方案。尽管这是本书的最后一章，但它将作为一个起点，帮助你考虑在迁移到云端时需要考虑哪些事项。

我们将涵盖以下主题的基础知识：

+   转移到云端

+   容器设计

+   持续集成流水线

+   持续部署流水线

+   自动化测试

我们将在本章中涵盖的主题和实践远非详尽，我们将进行一个宏观概述。有了这些基础知识，你可以开始加强你在每个领域的知识，为你的客户做出最终的设计决策。

# 根据场合设计

在之前的章节中，我们学到了针对非常具体的解决方案所需的一切。在这里，我们将讨论一般性的内容，你需要遵循或至少尝试遵循的基本规则或建议，以便你创建的每个设计。但不要被我接下来要说的所困惑；最佳实践本身并不存在。每个解决方案都将有其自己的特性、目标和独特的特点。始终努力满足你所处的情况和客户的业务需求。

然而，许多解决方案将不得不遵守某些行业标准，因为它们可能处理敏感信息。在这些类型的场景中，我们已经有了一套非常明确定义的规则和政策，我们的设计必须满足这些规则。这打破了我们所有设计都是不同的说法，但再次强调，这些是非常特定的行业的非常特定的场景。在处理敏感数据时，我们需要遵守的一些标准包括：

+   《健康保险可携带性和责任法案》（HIPAA）

+   《支付卡行业数据安全标准》（PCI-DSS）

+   《通用数据保护条例》（GDPR）

这些标准是固定的，无论是在本地还是国际上，并由各自的管理机构监管。但并非所有的设计模式或满足特定解决方案要求的方式都像这些那样清晰明了。

作为解决方案架构师，你将发现自己处于许多场景中，这将帮助你扩展你的作品集并将其应用于不同的解决方案。你创建的每个设计只有其最薄弱的环节才能够强大。在设计时，始终尝试看看你如何能够打破你的设计：

+   它在哪些地方存在故障点？

+   它在哪些地方存在瓶颈？

+   我的服务器能够承受负荷吗？

这些是你需要问自己的一些问题的几个例子。我们需要塑造我们的思维方式，并更经常地问自己“为什么？”为什么我们要以这种方式或那种方式做某事？质疑我们所做的每一个决定是至关重要的。

改变我们的思维方式是我们可以做的最好的事情，因为现在的技术发展速度比以往任何时候都要快。技术可能会随着时间的推移而发生变化，而我们今天实施的东西明天可能完全无法使用，但我们的思维方式将使我们能够适应并从所有必要的角度进行分析，以便我们取得成功。

每种情况和环境都是不同的，但在撰写本文时，我们可以说你将会处理两种主要类型的环境：

+   本地/裸金属环境

+   云环境

在本章中，我们将讨论你在这些环境中工作时需要处理的基本考虑因素。

# 本地环境

Linux 是适应性强的；它几乎可以在任何地方运行。如果未来几年我在割草机上发现 Linux 内核，我也不会感到惊讶。在 IT 变得越来越重要的当今世界，随着物联网的兴起，Linux 的存在前所未有地增加。因此，作为 Linux 架构师，我们需要准备几乎可以应对任何情况的设计。

在本地环境中，我们很可能面临两种情况：

+   裸金属服务器

+   **虚拟机**（**VMs**）

两者将非常不同，因为我们将有各种选项来使我们的解决方案更具弹性。

# 裸金属服务器

裸金属服务器非常适合需要大量资源运行的工作负载。小型工作负载不适合放在单个服务器上；例如，一个不会提供大量用户请求的小型网络应用在 64 核 1TB 内存的物理服务器上没有位置。这是对资源的浪费和糟糕的经济决策。大部分时间，这台服务器的 90%将是完全空闲的，浪费了宝贵的资源，可以用于其他用途。这些类型的应用应该放入虚拟机或完全容器化。

在将基础架构移至裸金属上或在裸金属上创建基础架构之前，我们应该了解所构建基础架构的应用程序的资源需求。

需要大量资源进行数据处理和高性能计算的系统将充分利用可用资源。以下解决方案是裸金属服务器上运行的示例：

+   Type 1/ Type 2 虚拟化监控器（**基于内核的虚拟机**（**KVM**），**Linux 容器**（**LXC**），XEN）

+   Linux 用于 SAP HANA

+   Apache Hadoop

+   Linux 用于 Oracle DB

+   大规模的 MongoDB 部署用于内存缓存

+   **高性能计算**（**HPC**）

内部应用程序规定其内存需求超过数百 GB 或数百 CPU 核心的所有应用程序都更适合在裸金属服务器上运行，因为 RAM/CPU 不会被用于不属于您为其设计服务器的工作负载的任何其他开销过程。

# 虚拟机

虚拟化监控器在裸金属服务器上也更好；因为它们将在多个托管的虚拟机之间共享资源，所以需要大量资源。需要注意的一点是，监控器的一些资源将被监控器本身消耗，这会在硬件中断和其他操作上产生资源开销。

有时，在构建物理服务器时，我们会非常关注应用程序所需的 CPU 核心。对于虚拟化监控器，CPU 时间优先分配给虚拟机，或者按照可用核心的先到先服务的原则分配给虚拟机；根据配置方式，CPU 资源在运行的虚拟机之间共享。相反，RAM 内存不会在虚拟机之间共享，我们需要在实施资源平衡时小心谨慎。部署具有必要 CPU 核心但具有足够 RAM 的服务器，可以满足我们可能面临的任何争用期的需求是需要考虑的。在单个主机上运行数百个虚拟机时，我们可能会很快耗尽内存并开始交换，这是我们要避免的情况。

在资源配置方面，我们还需要考虑的是，如果我们运行一组虚拟化监控器，可能会出现集群节点需要进行维护或由于意外故障而宕机的情况。正是因为这样的情况，我们应该始终留出一些资源，以便能够处理由于上述原因可能发生故障转移的虚拟机的额外意外工作负载。

在处理虚拟化程序时，你必须小心，因为你不会只在一个物理主机上运行单个工作负载。虚拟机的数量和虚拟机本身将始终变化，除非你配置了某种亲和规则。诸如你的网络接口卡支持多少网络带宽之类的事情至关重要。根据主机虚拟化程序的资源量，数十甚至数百个虚拟机将共享相同的网络硬件来执行它们的 I/O。例如，这就是决定是否需要 10GbE 网络卡而不是 1GbE 网络卡的地方。

在选择物理主机的网络接口时，还有一件事需要考虑，那就是你将使用的存储类型；例如，如果你正在考虑使用**网络文件系统**（NFS）解决方案或 iSCSI 解决方案，你必须记住，很多时候它们将共享与常规网络流量相同的接口。如果你知道你正在设计的基础架构将有非常拥挤的网络并且需要良好的存储性能，最好选择另一种方法，比如选择一个拥有专门用于存储 I/O 的独立硬件的光纤通道存储区域网络。

网络分割对于虚拟化环境、管理流量、应用程序网络流量和存储网络流量至关重要，这些流量应始终进行分割。你可以通过多种方式实现这一点，比如为每个目的分配专用的网络接口卡，或者通过 VLAN 标记。每个虚拟化程序都有自己的一套工具来实现分割，但其背后的思想是相同的。

# 云环境

与**云环境**合作为设计 IT 解决方案提供了大量选择。无论云服务提供商如何，你都可以从这些服务中进行选择：

+   **基础设施即服务**（IaaS）

+   **平台即服务**（PaaS）

+   **软件即服务**（SaaS）

你的选择将取决于你的客户在云架构模型方面的成熟度。但在我们甚至能谈论云环境的设计模式或最佳实践之前，我们需要讨论如何将你的本地环境迁移到云端，或者你如何开始将云作为客户基础架构的一部分。

# 通往云的旅程

这些迁移策略源自 Gartner 的研究。Gartner 还提出了第五种策略，称为**用 SaaS 替代**。

本节讨论了以下研究论文：

*通过回答五个关键问题制定有效的云计算策略，*Gartner，David W Cearley，2015 年 11 月，更新于 2017 年 6 月 23 日。

当迁移到云端时，我们不必把云看作目的地，而是看作一个旅程。尽管听起来有点俗套，但确实如此。每个客户通往云的道路都会不同；有些道路会很容易，而其他一些则会非常艰难。这将取决于是什么促使客户做出迁移决定，以及他们决定如何迁移他们的基础架构。一些客户可能决定不仅将基础架构迁移到 IaaS 模型，还要利用这次迁移，将一些工作负载现代化为 PaaS 甚至无服务器模型。无论选择哪种道路，每条道路都需要不同程度的准备工作。典型的过渡可能如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/3a2d9429-d251-4d44-b863-922c08de6c9b.png)

每一步都需要对应用程序或基础架构进行更大程度的变更。

我们可以将上述步骤视为一个更大旅程的一部分，该旅程始于对要迁移的资产的评估。

让我们更详细地探讨迁移的每一步。

# 评估

在这一步中，我们将评估我们想要迁移的工作负载。在确定迁移候选项后，我们应该始终对我们的虚拟机或物理服务器进行清点，并计算维护基础设施的**总拥有成本**（**TCO**）。硬件成本、支持维护合同、电费，甚至空间租金等都会在这里起作用。这将帮助我们了解在迁移到云上时我们将节省多少成本。这些数据对于说服管理层和任何可能对将基础设施迁移到云服务提供商的成本优势产生疑虑的 C 级决策者至关重要。

开始迁移的理想情况是寻找那些不需要整个基础架构迁移就可以投入生产的较小的应用程序。具有少量依赖关系的应用程序是开始评估的完美选择。需要考虑的依赖关系包括需要一起迁移的服务器、应用程序的网络需求（如端口和 IP 操作范围）。以下问题将帮助我们为成功迁移做好准备：

+   我使用的 Linux 发行版是否得到我要迁移到的云服务提供商的认可？

+   我是否正在运行云服务提供商支持的内核版本？

+   我是否需要安装任何额外的内核模块？

+   我的云服务提供商是否需要在我的操作系统上运行任何类型的代理？

有了这些问题的答案，我们可以开始执行实际的迁移。

# 迁移

在将基础架构迁移到云上时，有四种基本的方法：

+   **提取和迁移**

+   **重构**

+   **重新架构**

+   **重建**

这些方法中的每一种都将利用云的不同服务和不同功能。选择使用哪种方法将取决于许多因素，例如您需要多快迁移、您愿意为迁移付出多少努力，以及您是否希望在迁移过程中利用迁移并使您的工作负载现代化。

# 提取和迁移

这种方法实际上是重新托管，因为您将把您的本地物理服务器或虚拟机迁移到您云服务提供商的虚拟机中。这种方法是所有方法中最简单和最快的，因为您将按照本地环境将您的环境和应用程序迁移过去。对于这种方法，不需要进行代码更改或重新架构您的应用程序。在这里，您只需要利用您选择的云服务提供商的 IaaS 优势。

如果需要按需增加存储或计算资源的灵活性，以及无需硬件维护和管理，都是这种模式中可以利用的优势。

# 重构

通过**重构**，您的应用程序需要最少或不需要任何代码更改。通过这种方法，我们可以利用 IaaS 和 PaaS 功能的混合。将三层 Web 应用程序迁移到托管中间件和托管数据库是这种迁移模型的完美示例。

使用托管数据库或托管中间件，我们无需担心诸如操作系统管理、数据库引擎安装和管理、框架更新、安全补丁，甚至为负载平衡配置额外实例等问题，因为这一切都已经为我们处理好了。我们只需要上传我们的代码并选择我们需要运行的框架。我们仍然可以运行单片应用程序，只需要进行很少的代码更改；这种方法的主要目的是通过摆脱管理和配置等事务来进行迁移，从而增加我们工作负载的灵活性。

# 重新架构

**重新架构**在迁移时确实涉及对我们的应用程序进行重大更改，但这个阶段是我们现代化业务的阶段。

我们可以通过利用容器和 Kubernetes 等技术，将一个庞大的应用程序拆分成微服务。我们将使我们的应用程序更具可移植性、可扩展性、灵活性，并准备通过 DevOps 等方法交付。有了微服务、容器和 DevOps 带来的自动化，你不仅可以更快地将应用程序交付到生产环境，还可以更有效地利用应用程序运行的计算资源。

重新架构可能并不容易，也不是将工作负载迁移到云的最快方式，但从长远来看，它将为您带来实质性的优势和成本节约。

# 重建

重新架构需要进行重大的代码更改，但这种迁移模型的最终目标是充分利用迁移到云的机会，并创建所谓的**云原生应用**。

云原生应用是利用 PaaS 和 SaaS 等云服务的应用程序，这些应用程序旨在在云上运行。其中一些甚至可以完全在无服务器计算上运行。无服务器计算是直接在云服务上运行代码，或者使用云提供商已经提供的 API 或服务。将几个相互消耗并共同努力实现共同目标或结果的服务组合在一起，这就是我们所说的云原生应用。

迁移到云的整个理念是为了节省：在经济上节省，在维护上节省，在通过迁移到更具弹性和韧性的平台上节省恢复时间。但我们并不总是能自动地充分利用所有这些好处。迁移后，我们仍然需要做一些工作，以使我们的新云工作负载完全优化。

# 优化

也许如果您通过搬迁和转移来迁移您的基础设施，那么这个过程可能会很容易，而且在那个虚拟机上运行的任何工作负载可能已经在生产环境中，几乎没有任何变化。问题在于，您的虚拟机仍然与在本地环境中一样大。您仍然让虚拟机只使用其实际总计算资源的一小部分。在云中，这是在浪费金钱，因为您支付虚拟机运行的时间，但您支付这些时间的价格是基于该虚拟机的总资源量，无论您是否使用了其中的 100%。

这个阶段是我们实际开始进行适当的大小调整和优化我们的基础设施，以实际使用我们真正需要的资源，以充分利用云的弹性。所有云服务提供商都有工具和服务，您可以使用这些工具来监视虚拟机和其他服务的资源消耗。有了这些工具，我们可以轻松地识别和解决我们的大小需求，以一种成本有效的方式。

云的弹性不仅允许我们根据需求调整资源，而且无需等待 IT 运维团队在我们的虚拟化主机或专用物理服务器资源不足时分配或购买新硬件。

我们还可以根据我们设定的资源阈值按需为我们正在使用的服务提供额外的虚拟机或实例。对这些资源的请求会自动地负载均衡到我们的额外实例，这样我们只需要在资源争用期间支付额外的资源。

优化并不仅仅是为了获得更好的价格而减少虚拟机的大小。我们可以优化的其他领域包括管理和上市时间。采用 PaaS 和 SaaS 等方法可以帮助我们实现这一点。

一旦我们的应用程序在云上的虚拟机上运行，我们可以轻松地开始过渡到这些更受管理的服务。受管理的服务帮助我们忘记操作系统的维护或中间件配置，我们的开发人员可以花更多时间实际开发和部署应用程序，而不是与运维团队争论库需要更新以使最新版本的生产应用程序运行，这最终使我们的上市时间更快，管理或操作系统支持合同的花费更少。

更快的上市时间，更少的管理，以及运维和开发之间更少的冲突，这就是 DevOps 所关注的。我们在迁移阶段的几个阶段中提到了 DevOps，但让我们更深入地了解一下 DevOps 是什么，以及它试图在更接近的层面上实现什么。

# DevOps

综合而言，DevOps 是开发和运维的结合。它是开发人员和系统管理员之间的联合和协作，使得 DevOps 成为可能。请注意我们说的是协作；重要的是要理解协作是 DevOps 的核心。与 Scrum 框架等有权威的方法不同，DevOps 没有标准，但它遵循一套实践，这些实践源自这两个团队之间的文化交流，以实现更短的开发周期和更频繁的部署，采用敏捷方法。

你经常会看到 DevOps 这个术语被错误使用，例如：

+   **职位（DevOps 工程师）**：DevOps 的性质是跨运维和开发团队的协作，因此 DevOps 不是一个职位或一个专门从事 DevOps 的团队。

+   **一套工具**：用于帮助实现 DevOps 背后目标的工具也经常被混淆。Kubernetes、Docker 和 Jenkins 经常被误解为 DevOps，但它们只是达到目的的手段。

+   **标准**：正如我们之前提到的，DevOps 运动没有任何管理其实践和流程的权威；实施和遵循一套基本实践，并根据自身业务需求进行调整的是人们。

我们现在知道 DevOps 是一种文化运动，这给我们带来了更频繁的开发周期、频率和运维与开发之间的整合。现在，让我们了解采用 DevOps 的好处背后的问题。

# 整体瀑布

传统的软件应用程序开发方法称为**瀑布**。瀑布是一种线性顺序的软件开发方式；基本上，你只能朝一个方向前进。它是从制造业和建筑业中被软件工程采用的。瀑布模型的步骤如下：

1.  需求

1.  设计

1.  实施

1.  验证

1.  维护

主要问题在于，由于这种方法是为制造业和建筑业而发明的，它根本不具备敏捷性。在这些行业中，你面临的每一个变化或问题都可能让你付出很大的代价，因此在进入下一个阶段之前，必须考虑所有的预防措施。因此，每个阶段都需要相当长的时间，因此上市时间大大缩短。

在这种方法中，在甚至开始创建应用程序之前，开发人员必须设计所有的特性，并且在编写一行代码之前就花费了大量时间进行讨论和规划。这种情况对这种方法的起源来说是有意义的，因为如果你正在建造一座摩天大楼或者一座住宅，你希望在开始建造之前就知道它将如何设计和结构。在软件开发中，你获得反馈越快，就能越快地适应并进行必要的更改以满足客户的需求。在瀑布模型中，直到产品几乎准备好并且更改更难实施时才提供反馈。

瀑布模型本质上是庞大而笨重的，即使我们有不同的团队在产品的不同特性上工作，最终所有这些特性都会被编译在一起，以交付一个单一的大版本。对于这种类型的单体应用，如果有质量保证（QA）团队，他们必须测试该版本的所有特性。这需要很长时间，甚至会进一步增加产品上市的时间。最糟糕的情况是需要进行更改或者一个错误通过了 QA 进入生产。回滚将意味着整个版本的发布，而不仅仅是带有错误的版本，这在进行大版本发布时会带来很大的风险。

# 敏捷解决庞大的问题

瀑布模型让我们太晚才意识到我们认为会起作用的事情在安装阶段或者甚至在生产阶段并没有按计划进行。进行这些更改涉及很多步骤，而且调整速度缓慢而痛苦。

软件发展迅速，客户的需求可能会在设计过程中发生变化。这就是为什么我们需要比瀑布模型更敏捷和灵活的方法。我们获得反馈越快，就能越快地适应并交付客户的确切期望。

这正是敏捷方法的用途。敏捷旨在通过多次发布软件，每次都经过一系列测试和反馈，以便更快地获得并以更敏捷的方式进行更改和调整。

敏捷是一个改变游戏规则的方法，但它在运维和开发之间产生了冲突。

部署更频繁可能会变得不规范，并且每次都会有所不同，如果不同的工程师执行部署。比如说你在晚上部署，第二天早上负责部署的人和上次部署的工程师可能会有完全不同的部署方式。这种情况会产生差异，并可能导致问题。例如，如果发生了什么事情需要回滚，负责回滚的人可能不知道部署时采取的步骤，以便回滚更改。

这些发布可能会不可预测地影响系统的可用性。运维工程师的绩效评估是他们管理的系统的稳定性，他们有兴趣保持系统的稳定。将不可预测的更改部署到生产环境是他们想要避免的。另一方面，开发人员的绩效评估是他们能够多快地将新的更改、功能和发布投入生产。你可以看到这两个团队有完全相反的目标，他们几乎必须互相斗争来实现这些目标。

团队之间不同的目标使每个团队都处于孤立状态。这会产生信息孤岛，并把问题或应用程序抛到另一个团队那里。这会导致非协作的工作环境，每个人都互相指责，事情进展得更慢，而不是解决问题。

# 持续的 CI/CD 文化

到目前为止，我觉得你已经注意到我们还没有谈论任何使 DevOps 成为可能的工具。这是因为工具不会解决所有这些类型的问题。它们将帮助您和您的客户强化 DevOps 文化，但并不是使 DevOps 成为可能的原因。

在我们交付产品之前进行标准化和测试对于敏捷和 DevOps 至关重要，工具将帮助我们实现这两个目标。让我们来看看敏捷工作流程和 DevOps 工作流程：

以下是敏捷工作流程的概述：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/aee6ce74-5f90-4690-97e0-50ba754b576a.png)

以下是与 DevOps 的比较：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-arch/img/1e4a7937-d1ea-4444-9564-fb1766d52748.png)

很明显，它们两者是相辅相成的，它们彼此重叠，因为它们追求相同的目标。DevOps 有额外的步骤，比如操作和监控，这些步骤发生在代码部署之后。这些步骤非常直观；监控包括监视我们的应用在生产环境中的行为，检查它是否存在任何错误，或者它是否正在使用分配给它的所有资源。操作硬件、虚拟机或 PaaS 的部署位置。

**持续部署**（CD）和**持续集成**（CI）的理念是为了给我们带来标准化和确保变更和发布尽快进入生产并且失败最少的手段。如果发生故障，我们也可以快速轻松地回滚。CI/CD 的整个目的是自动化手动流程，许多公司仍然手动编译发布，并且通过电子邮件发送二进制文件和部署代码的说明给运维人员。为了实现 CI/CD，我们有工具可以帮助我们自动化整个构建、测试、部署和发布周期。

典型的 CI/CD 流水线是由对 Git 存储库的提交触发的，然后触发自动化构建过程，通常生成一个构件或一个发布，然后触发应用程序的自动化测试和自动化部署。

让我们来看看一些不同的开源工具，对每个工具进行简要解释，并说明它属于 DevOps 周期的哪个阶段。

这还远远不是一个详尽的清单，解释只是它们用途的简要总结：

+   **代码**：

+   **Git**：一个版本控制系统，允许开发人员拥有他们的代码分布式存储库，并跟踪开发周期中的变更。

+   **GitHub、GitLab、Bitbucket**：这三个都是 Git 类型的存储库而不是工具。然而，它们值得一提，因为它们是行业中最常用的公共和私有 Git 存储库。

+   **Apache 子版本**（SVN）：这是另一个版本控制系统。尽管自从 Git 发布以来它不再像以前那样受欢迎，但它值得一提，因为您可能会在传统环境中遇到它。

+   **构建**：

+   **Docker**：Docker，正如我们在第十四章中讨论的那样，*Getting Your Hands Salty*，是一个工具，您可以使用它来构建您的容器镜像，而不受应用程序使用的语言的限制。Docker 在底层使用**Buildkit**，它也可以作为一个独立产品用于构建 Docker 镜像。

+   **Apache Ant**：这个工具是第一个取代为 Java 应用程序制作的著名 Unix 构建二进制文件的工具。它使用`xml`来定义构建的步骤。这个工具主要用于 Java 应用程序。

+   **Apache Maven**：Apache Maven 也是另一个 Java 构建工具，但它解决了 Apache Ant 缺乏的依赖管理等问题。

+   **Gradle**：Gradle 是基于 Apache Ant 和 Apache Maven 构建的，但 Gradle 使用自己基于 Groovy 的特定语言来定义所需的步骤。Gradle 是最模块化的，几乎所有功能都是通过插件添加的。

+   **Grunt**：这是 JavaScript 的 Ant 或 Maven 等效工具；它自动化并运行任务，如 linting、单元测试、最小化和编译。Grunt 高度模块化，因为有成千上万的插件可用。

+   **测试**：

+   **Selenium**：这主要是一个 Web 应用程序测试工具，可以运行在大多数现代 Web 浏览器上。使用 Selenium，您不一定需要了解测试编程语言，因为它提供了一个 IDE 和使用几种最流行的编程语言的选项。

+   **Apache JMeter**：这基本上是一个负载性能工具，它在服务器上生成大量负载，以测试静态和动态内容，以便您可以分析其在不同负载类型下的性能。

+   **Appium**：另一方面，Appium 不仅可以测试 Web 应用程序，还可以对移动和桌面应用程序进行测试。

+   **发布、部署、管理、编排、操作**：

+   **Jenkins**：这可能是 DevOps 文化中使用最广泛的工具。Jenkins 是一个自动化服务器，通过调用构建和发布过程的自动化触发器，以及在管道中配置的任何自动化测试，使所有步骤都成为可能。

+   **Ansible**：这主要是一个配置管理工具，但它也可以通过其模块化帮助我们发布我们的应用程序，并提供一种便捷的方式来开发您自己的 playbooks 以运行在一组服务器上。

+   **Puppet**：这是另一个配置管理工具，它帮助我们维护配置并管理环境服务器上的软件包补丁安装。

+   **Helm**：将 Helm 视为 Kubernetes 的`yum`或`apt`：它本身无法自动化任何部署过程，但借助诸如 Jenkins 之类的工具，您可以使用它将自定义图表部署到 Kubernetes，并在需要回滚时保留发布历史。

+   **Monitor**：

+   **Nagios**：这是经典的监控集中工具，监控从系统性能到服务状态等各种内容。

+   **Prometheus**：这是云原生计算基金会旗下的一个项目。它允许我们创建自己的指标和警报。

+   **Fluentbit**：这允许您收集多个日志和/或数据，并将其发送到多个目的地以进行日志收集或处理。

# 总结

作为最后一章，我们总结了在设计解决方案时需要考虑的一些因素。在本章中，我们介绍了在处理不同场景时应该牢记的事项。

了解我们将在哪里以及如何部署我们的解决方案有助于我们了解可能存在的要求类型；例如，某些行业将有无法忽视的硬性要求，如 HIPAA、PCI 和 GDPR。

然后，我们谈到了部署本地解决方案以及不同的工作负载对裸金属的更好适用性，以及在实施虚拟机时需要考虑的因素。

我们提到了如何转移到云端并不像点击一个门户网站然后等待那样简单，而是一个旅程，因为它允许根据云端提供的众多选项对工作负载进行现代化。

此外，我们提到了迁移现有工作负载的不同方法，如提升和转移、重构、重新架构和重建。

最后，我们描述了 DevOps 如何通过统一开发和运营方面来帮助塑造行业，以及这如何与 CI/CD 改变了软件部署和使用方式相关联。

# 问题

1.  HIPAA 是什么？

1.  哪些工作负载更适合在裸金属上运行？

1.  虚拟化监视器应该在裸金属上运行吗？

1.  虚拟机共享资源吗？

1.  什么是网络分割？

1.  什么是提升和转移？

1.  什么是重构？

1.  什么是重新架构？

# 进一步阅读

**大型计算机程序的生产**：[`sunset.usc.edu/csse/TECHRPTS/1983/usccse83-501/usccse83-501.pdf`](http://sunset.usc.edu/csse/TECHRPTS/1983/usccse83-501/usccse83-501.pdf)

管理大型软件系统的开发：[`www-scf.usc.edu/~csci201/lectures/Lecture11/royce1970.pdf`](http://www-scf.usc.edu/~csci201/lectures/Lecture11/royce1970.pdf)

Azure 迁移中心：[`azure.microsoft.com/en-gb/migration/get-started/`](https://azure.microsoft.com/en-gb/migration/get-started/)

将数据中心迁移到云 IaaS 的 3 条路径：[`www.gartner.com/smarterwithgartner/3-journeys-for-migrating-a-data-center-to-cloud-iaas/`](https://www.gartner.com/smarterwithgartner/3-journeys-for-migrating-a-data-center-to-cloud-iaas/)


# 第十六章：评估

# 第一章：设计方法简介

1.  问题陈述→信息收集→解决方案提议→实施。

1.  因为它允许建立正确的要求。

1.  为客户选择合适的解决方案留出空间。

1.  在“分析问题并提出正确问题”部分进行了探讨。

1.  概念验证。

1.  实际的解决方案已交付并测试。

1.  它使我们能够探索解决方案的不同概念，以及实际工作环境的解决方案。

# 第二章：定义 GlusterFS 存储

1.  第五章，*在 Gluster 系统中分析性能*进一步分析了这一点。

1.  文件存储更适合 GlusterFS 的工作方式。

1.  几乎所有云提供商现在都提供对象存储。

1.  文件存储、块存储（通过 iSCSI Initiator）和对象存储（通过插件）。

1.  不，但它确实为项目做出了贡献。

1.  GlusterFS 是免费的开源软件；只需从您喜欢的软件包管理器下载即可。

1.  它通过地理复制功能实现。

# 第三章：设计存储集群

1.  这取决于所使用的卷类型，但 2 个 CPU 和 4GB 以上的 RAM 是一个很好的起点。

1.  GlusterFS 将使用 brick 的文件系统缓存机制。

1.  这是一个快速的存储层，I/O 将在此处提供，而不是转到较慢的存储。缓存可以是 RAM 或更快的存储介质，如固态硬盘。

1.  随着并发性的增加，软件将需要更多的 CPU 周期来处理请求。

1.  分布式将聚合空间，复制将镜像数据，因此“减半”空间，分散将聚合空间，但将消耗一个节点用于奇偶校验。将其视为 RAID5。

1.  取决于许多变量，如保留期、数据进入等等...

1.  预期的数据增长量。

1.  吞吐量是一定时间内给定数据量的函数，通常显示为 MB/s 或每秒兆字节

**每秒输入输出操作数**（**IOPS**）是每秒一定数量的操作的函数

**I/O 大小**指的是设备执行的请求大小

1.  GlusterFS 使用的存储位置的布局。

1.  GlusterFS 的数据从一个集群复制到另一个集群的过程，通常位于不同的地理位置。

# 第四章：在云基础架构上使用 GlusterFS

1.  GlusterFS 用于存储实际数据的存储位置。

1.  Z 文件系统，由 Sun Microsystems 创建并后来开源的高级文件系统。

1.  一个 ZFS 存储池。

1.  用于读取请求的磁盘，通常比 zpool 中使用的磁盘更快，延迟更低。

1.  通常通过操作系统的软件包管理器，如 yum。

1.  一组 GlusterFS 节点，将参与同一集群。

1.  Gluster 卷创建<卷名称><卷类型><节点数><节点和 brick 路径>。

1.  此设置控制将用于缓存的内存量。

1.  自适应替换缓存，这是 ZFS 的缓存算法。

# 第五章：在 Gluster 系统中分析性能

1.  每秒兆字节，吞吐量测量。

1.  显示 ZFS 的 I/O 统计信息。

1.  sysstat 软件包的一部分，用于块设备 I/O 统计。

1.  这是读取延迟，以毫秒为单位测量。

1.  CPU 等待未完成 I/O 的时间量。

1.  灵活 I/O 测试，用于 I/O 基准测试的工具。

1.  通过配置文件或直接通过命令传递参数。

1.  一个告诉 FIO 如何运行测试的文件。

1.  通过故意杀死其中一个节点。

1.  通过增加节点上的资源或增加磁盘大小。

# 第六章：创建高可用的自愈架构

1.  主要的 Kubernetes 组件分为控制平面和 API 对象。

1.  它们三个都是由三个主要的公共云提供商 Google、亚马逊和微软提供的托管 Kubernetes 解决方案。

1.  容器的攻击面较小，但这并不意味着它们不会受到利用，但主要的容器运行时项目都得到了很好的维护，如果检测到利用，将会迅速解决。

1.  这将取决于您尝试运行的应用程序类型以及您对技术的熟悉程度。将应用程序迁移到容器通常很容易，但以最有效的方式进行迁移需要工作。

1.  不，您可以在 Windows 上找到 Docker Engine，并且在撰写本文时，Kubernetes Windows 节点处于测试版。

# 第七章：理解 Kubernetes 集群的核心组件

1.  Kubernetes，在撰写本文时，是市场上最主要的容器编排器。

1.  Kubernetes 由组成集群的二进制文件和称为 API 对象的逻辑对象组成。

1.  Kubernetes API 对象是编排器管理的逻辑对象。

1.  我们可以运行编排的容器化工作负载。

1.  容器编排器是负责管理我们运行的容器和与保持我们的工作负载高度可用相关的不同任务的工具。

1.  Pod 是 Kubernetes 的最小逻辑对象，它封装了一个或多个共享命名空间中的容器。

1.  部署是由 Kubernetes 复制控制器管理的一组复制的 Pod。

# 第八章：在 Azure 上设计 Kubernetes

1.  由于 ETCD 的大多数机制，通常首选奇数以便能够始终获得多数票。

1.  是的，但它也可以在单独的一组笔记本上运行。

1.  由于心跳和领导者选举频率，建议使用较低的延迟。

1.  工作节点或节点是负责运行容器工作负载的集群成员。

1.  工作负载的类型以及每种工作负载将运行的容器数量。

1.  所有存储提供商或提供者都可以在此处找到：[`kubernetes.io/docs/concepts/storage/storage-classes/#provisioner`](https://kubernetes.io/docs/concepts/storage/storage-classes/#provisioner)

1.  需要负载均衡器来将请求发送到所有复制的 Pod。

1.  命名空间可用于逻辑上分区我们的集群，并为每个逻辑分区分配角色和资源。

# 第九章：部署和配置 Kubernetes

1.  有几种安装 Kubernetes 的方法，从自动配置工具如`kubeadm`和`kubespray`到完全手动安装。您可以在以下链接找到有关安装方法的更多信息：[`kubernetes.io/docs/setup/`](https://kubernetes.io/docs/setup/)

1.  `kubeconfig`文件包含与 API 服务器通信和认证所需的所有必要信息。

1.  您可以使用多种工具创建 SSL 证书，在本书中我们使用了`cffssl`。但您也可以使用`openssl`和`easyrsa`。

1.  **Azure Kubernetes Services**（**AKS**）是微软为其公共云 Azure 提供的托管 Kubernetes 解决方案。

1.  Azure CLI 可以在任何操作系统中使用，因为它是基于 Python 的命令行界面。

1.  您可以通过 Azure CLI、PowerShell 或 Azure GUI 创建资源组。

1.  您可以在以下链接找到安装 etcd 的不同方法：[`play.etcd.io/install`](http://play.etcd.io/install)

# 第十章：使用 ELK 堆栈进行监控

1.  积极收集数据的过程。

1.  通过了解使用趋势，可以根据实际数据做出购买更多资源等决策。

1.  通过将数据放在一个地方，可以在事件发生之前主动检测到事件。

1.  通过了解存储系统的正常行为，从而为性能提供基线。

1.  当看到不应该出现的峰值时，这可能意味着不稳定的行为。

1.  与通过环境中的每个主机进行检查相比，可以通过单个集中位置进行检查。

1.  用于数据索引和分析的软件。

1.  Elasticsearch 以 json 格式存储数据。

1.  Logstash 是一个数据处理解析器，允许在发送到 Elasticsearch 之前对数据进行操作。

1.  Kibana 为 Elasticsearch 提供可视化界面，允许数据轻松可视化。

# 第十一章：设计 ELK 堆栈

1.  至少需要 2 个 CPU 核心才能在较小的部署中实现最佳功能。

1.  至少 2GHz。

1.  较慢或少于 2 个 CPU 主要影响 Elasticsearch 的启动时间、索引速率和延迟。

1.  内核使用可用的 RAM 来缓存对文件系统的请求。

1.  如果发生交换，搜索延迟将受到严重影响。

1.  如果内存不足，Elasticsearch 将无法启动，一旦运行，如果内存不足，OOM 将终止 Elasticsearch。

1.  最低要求是 2.5GB，但建议使用 4GB。

1.  `/var/lib/elasticsearch`

1.  较低的延迟有助于索引/搜索延迟。

1.  2GB RAM 和 1 个 CPU。

1.  这是一个存储位置，logstash 将在崩溃的情况下持续存储队列。

1.  有多少用户将同时访问仪表板。

# 第十二章：使用 Elasticsearch、Logstash 和 Kibana 管理日志

1.  Elasticsearch 可以通过软件包管理器安装。

1.  这是通过 parted 完成的。

1.  将磁盘的 UUID 添加到`/etc/fstab`。

1.  `/etc/elasticsearch/elasticsearch.yml`

1.  这给集群命名，名称应在节点之间保持一致，以便每个节点加入相同的集群。

1.  数字由`(N/2)+1`决定。

1.  通过使用相同的 cluster.name 设置，第二个节点将加入相同的集群。

1.  添加存储库，通过`yum`安装，为 logstash 分区磁盘。

1.  这是一个存储位置，logstash 将在崩溃的情况下持续存储队列。

1.  协调节点是一个 Elasticsearch 节点，不接受输入，不存储数据，也不参与主/从选举。

1.  Beats 是来自 Elastic.co 的轻量级数据船运工具。

1.  Filebeat 的功能是从诸如`syslog`、apache 和其他来源收集日志，然后将其发送到 Elasticsearch 或 Logstash。

# 第十三章：用 Salty Solutions 解决管理问题

1.  是维护现有 IT 基础设施的任务。

1.  集中所有基础设施，无论其操作系统或架构如何。

1.  Puppet、Chef、Ansible、Spacewalk、SaltStack 等等。

1.  编写期望状态的特定语言，可以描述 IT 基础设施的状态。

1.  推送和拉取。

1.  Salt 是一个开源项目/软件，旨在解决系统管理的许多挑战。

1.  主节点和从节点。

# 第十四章：设计盐溶液并安装软件

1.  任何 Linux 发行版。

1.  一个自管理节点是最低要求。

1.  为我们的 SaltStack 提供高可用性和负载平衡。

1.  手动安装二进制文件，以及通过引导脚本。

1.  通过它们的密钥。

1.  通过`test.ping`函数。

1.  Grains 包含特定于从属者的信息（元数据）或标签。Pillars 包含配置和敏感信息。

# 第十五章：设计最佳实践

1.  HIPAA 代表《健康保险可携带性和责任法》，这是处理健康和医疗数据的标准。

1.  类型 1/类型 2 的 Hypervisors（基于内核的虚拟机（KVM），Linux 容器（LXC），XEN）

用于 SAP HANA 的 Linux

Apache Hadoop

用于 Oracle DB 的 Linux

大型 MongoDB 部署用于内存缓存

高性能计算（HPC）

1.  是的，理想情况下，虚拟化程序需要访问资源，以更有效地为虚拟机提供资源。

1.  是的，CPU 是主要的共享资源，因为物理 CPU 必须为同一节点中的所有 VM 提供周期。

1.  允许不同的网络流量通过不同的 NIC /子网。

1.  这是一种迁移方法，可以将现有工作负载从本地迁移到云端。

1.  这是一种迁移方法，利用架构的一些变化，以利用云端提供的解决方案。

1.  这是一种迁移方法，涉及将解决方案重新架构到云端。
