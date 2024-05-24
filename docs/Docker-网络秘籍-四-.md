# Docker 网络秘籍（四）

> 原文：[`zh.annas-archive.org/md5/15C8E8C8C0D58C74AF1054F5CB887C66`](https://zh.annas-archive.org/md5/15C8E8C8C0D58C74AF1054F5CB887C66)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 Flannel

在本章中，我们将涵盖以下配方：

+   安装和配置 Flannel

+   将 Flannel 与 Docker 集成

+   使用 VXLAN 后端

+   使用主机网关后端

+   指定 Flannel 选项

# 介绍

Flannel 是由**CoreOS**团队开发的 Docker 的第三方网络解决方案。Flannel 是早期旨在为每个容器提供唯一可路由 IP 地址的项目之一。这消除了跨主机容器到容器通信需要使用发布端口的要求。与我们审查过的其他一些解决方案一样，Flannel 使用键值存储来跟踪分配和各种其他配置设置。但是，与 Weave 不同，Flannel 不提供与 Docker 服务的直接集成，也不提供插件。相反，Flannel 依赖于您告诉 Docker 使用 Flannel 网络来配置容器。在本章中，我们将介绍如何安装 Flannel 以及其各种配置选项。

# 安装和配置 Flannel

在这个教程中，我们将介绍安装 Flannel。Flannel 需要安装一个密钥存储和 Flannel 服务。由于每个服务的依赖关系，它们需要在 Docker 主机上配置为实际服务。为此，我们将利用`systemd`单元文件来定义每个相应的服务。

## 准备工作

在本示例中，我们将使用与第三章中使用的相同的实验拓扑，*用户定义的网络*，在那里我们讨论了用户定义的覆盖网络：

![准备工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_08_01.jpg)

你需要一对主机，最好其中一些位于不同的子网上。假设在这个实验中使用的 Docker 主机处于它们的默认配置中。在某些情况下，我们所做的更改可能需要您具有系统的根级访问权限。

## 如何做…

如前所述，Flannel 依赖于一个键值存储来向参与 Flannel 网络的所有节点提供信息。在其他示例中，我们运行了基于容器的键值存储，如 Consul，以提供此功能。由于 Flannel 是由 CoreOS 构建的，我们将利用他们的键值存储`etcd`。虽然`etcd`以容器格式提供，但由于 Flannel 工作所需的一些先决条件，我们无法轻松使用基于容器的版本。也就是说，我们将下载`etcd`和 Flannel 的二进制文件，并在我们的主机上将它们作为服务运行。

让我们从`etcd`开始，因为它是 Flannel 的先决条件。你需要做的第一件事是下载代码。在这个例子中，我们将利用`etcd`版本 3.0.12，并在主机`docker1`上运行键值存储。要下载二进制文件，我们将运行以下命令：

```
user@docker1:~$ curl -LO \
https://github.com/coreos/etcd/releases/download/v3.0.12/\
etcd-v3.0.12-linux-amd64.tar.gz
```

下载完成后，我们可以使用以下命令从存档中提取二进制文件：

```
user@docker1:~$ tar xzvf etcd-v3.0.12-linux-amd64.tar.gz
```

然后我们可以将需要的二进制文件移动到正确的位置，使它们可以执行。在这种情况下，位置是`/usr/bin`，我们想要的二进制文件是`etcd`服务本身以及其命令行工具`etcdctl`：

```
user@docker1:~$ cd etcd-v3.0.12-linux-amd64
user@docker1:~/etcd-v2.3.7-linux-amd64$ sudo mv etcd /usr/bin/
user@docker1:~/etcd-v2.3.7-linux-amd64$ sudo mv etcdctl /usr/bin/
```

现在我们已经把所有的部件都放在了正确的位置，我们需要做的最后一件事就是在系统上创建一个服务，来负责运行`etcd`。由于我们的 Ubuntu 版本使用`systemd`，我们需要为`etcd`服务创建一个 unit 文件。要创建服务定义，您可以在`/lib/systemd/system/`目录中创建一个服务 unit 文件：

```
user@docker1:~$  sudo vi /lib/systemd/system/etcd.service
```

然后，您可以创建一个运行`etcd`的服务定义。`etcd`服务的一个示例 unit 文件如下所示：

```
[Unit]
Description=etcd key-value store
Documentation=https://github.com/coreos/etcd
After=network.target

[Service]
Environment=DAEMON_ARGS=
Environment=ETCD_NAME=%H
Environment=ETCD_ADVERTISE_CLIENT_URLS=http://0.0.0.0:2379
Environment=ETCD_LISTEN_CLIENT_URLS=http://0.0.0.0:2379
Environment=ETCD_LISTEN_PEER_URLS=http://0.0.0.0:2378
Environment=ETCD_DATA_DIR=/var/lib/etcd/default
Type=notify
ExecStart=/usr/bin/etcd $DAEMON_ARGS
Restart=always
RestartSec=10s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### 注意

请记住，`systemd`可以根据您的要求以许多不同的方式进行配置。前面给出的 unit 文件演示了配置`etcd`作为服务的一种方式。

一旦 unit 文件就位，我们可以重新加载`systemd`，然后启用并启动服务：

```
user@docker1:~$ sudo systemctl daemon-reload
user@docker1:~$ sudo systemctl enable etcd
user@docker1:~$ sudo systemctl start etcd
```

如果由于某种原因服务无法启动或保持启动状态，您可以使用`systemctl status etcd`命令来检查服务的状态：

```
user@docker1:~$ systemctl status etcd
  etcd.service - etcd key-value store
   Loaded: loaded (/lib/systemd/system/etcd.service; enabled; vendor preset: enabled)
   Active: active (running) since Tue 2016-10-11 13:41:01 CDT; 1h 30min ago
     Docs: https://github.com/coreos/etcd
 Main PID: 17486 (etcd)
    Tasks: 8
   Memory: 8.5M
      CPU: 22.095s
   CGroup: /system.slice/etcd.service
           └─17486 /usr/bin/etcd

Oct 11 13:41:01 docker1 etcd[17486]: setting up the initial cluster version to 3.0
Oct 11 13:41:01 docker1 etcd[17486]: published {Name:docker1 **ClientURLs:[http://0.0.0.0:2379]}** to cluster cdf818194e3a8c32
Oct 11 13:41:01 docker1 etcd[17486]: ready to serve client requests
Oct 11 13:41:01 docker1 etcd[17486]: **serving insecure client requests on 0.0.0.0:2379, this is strongly  iscouraged!
Oct 11 13:41:01 docker1 systemd[1]: Started etcd key-value store.
Oct 11 13:41:01 docker1 etcd[17486]: set the initial cluster version to 3.0
Oct 11 13:41:01 docker1 etcd[17486]: enabled capabilities for version 3.0
Oct 11 15:04:20 docker1 etcd[17486]: start to snapshot (applied: 10001, lastsnap: 0)
Oct 11 15:04:20 docker1 etcd[17486]: saved snapshot at index 10001
Oct 11 15:04:20 docker1 etcd[17486]: compacted raft log at 5001
user@docker1:~$
```

稍后，如果您在使用启用 Flannel 的节点与`etcd`通信时遇到问题，请检查并确保`etcd`允许在所有接口（`0.0.0.0`）上访问，如前面加粗的输出所示。这在示例单元文件中有定义，但如果未定义，`etcd`将默认仅在本地环回接口（`127.0.0.1`）上侦听。这将阻止远程服务器访问该服务。

### 注意

由于键值存储配置是明确为了演示 Flannel 而进行的，我们不会涵盖键值存储的基础知识。这些配置选项足以让您在单个节点上运行，并且不打算在生产环境中使用。在将其用于生产环境之前，请确保您了解`etcd`的工作原理。

一旦启动了`etcd`服务，我们就可以使用`etcdctl`命令行工具来配置 Flannel 的一些基本设置：

```
user@docker1:~$ etcdctl mk /coreos.com/network/config \
'{"Network":"10.100.0.0/16"}'
```

我们将在以后的教程中讨论这些配置选项，但现在只需知道我们定义为`Network`参数的子网定义了 Flannel 的全局范围。

现在我们已经配置了`etcd`，我们可以专注于配置 Flannel 本身。将 Flannel 配置为系统服务与我们刚刚为`etcd`所做的非常相似。主要区别在于我们将在所有四个实验室主机上进行相同的配置，而键值存储只在单个主机上配置。我们将展示在单个主机`docker4`上安装 Flannel，但您需要在实验室环境中的每个主机上重复这些步骤，以便成为 Flannel 网络的成员：

首先，我们将下载 Flannel 二进制文件。在本例中，我们将使用版本 0.5.5：

```
user@docker4:~$ cd /tmp/
user@docker4:/tmp$ curl -LO \
https://github.com/coreos/flannel/releases/download/v0.6.2/\
flannel-v0.6.2-linux-amd64.tar.gz
```

然后，我们需要从存档中提取文件并将`flanneld`二进制文件移动到正确的位置。请注意，与`etcd`一样，没有命令行工具与 Flannel 交互：

```
user@docker4:/tmp$ tar xzvf flannel-v0.6.2-linux-amd64.tar.gz
user@docker4:/tmp$ sudo mv flanneld /usr/bin/
```

与`etcd`一样，我们希望定义一个`systemd`单元文件，以便我们可以在每个主机上将`flanneld`作为服务运行。要创建服务定义，您可以在`/lib/systemd/system/`目录中创建另一个服务单元文件：

```
user@docker4:/tmp$ sudo vi /lib/systemd/system/flanneld.service
```

然后，您可以创建一个运行`etcd`的服务定义。`etcd`服务的示例单元文件如下所示：

```
[Unit]
Description=Flannel Network Fabric
Documentation=https://github.com/coreos/flannel
Before=docker.service
After=etcd.service

[Service]
Environment='DAEMON_ARGS=--etcd-endpoints=http://10.10.10.101:2379'
Type=notify
ExecStart=/usr/bin/flanneld $DAEMON_ARGS
Restart=always
RestartSec=10s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

一旦单元文件就位，我们可以重新加载`systemd`，然后启用并启动服务：

```
user@docker4:/tmp$ sudo systemctl daemon-reload
user@docker4:/tmp$ sudo systemctl enable flanneld
user@docker4:/tmp$ sudo systemctl start flanneld
```

如果由于某种原因服务无法启动或保持启动状态，您可以使用`systemctl status flanneld`命令来检查服务的状态：

```
user@docker4:/tmp$ systemctl status flanneld
  flanneld.service - Flannel Network Fabric
   Loaded: loaded (/lib/systemd/system/flanneld.service; enabled; vendor preset: enabled)
   Active: active (running) since Wed 2016-10-12 08:50:54 CDT; 6s ago
     Docs: https://github.com/coreos/flannel
 Main PID: 25161 (flanneld)
    Tasks: 6
   Memory: 3.3M
      CPU: 12ms
   CGroup: /system.slice/flanneld.service
           └─25161 /usr/bin/flanneld --etcd-endpoints=http://10.10.10.101:2379

Oct 12 08:50:54 docker4 systemd[1]: Starting Flannel Network Fabric...
Oct 12 08:50:54 docker4 flanneld[25161]: I1012 08:50:54.409928 25161 main.go:126] Installing signal handlers
Oct 12 08:50:54 docker4 flanneld[25161]: I1012 08:50:54.410384 25161 manager.go:133] Determining IP address of default interface
Oct 12 08:50:54 docker4 flanneld[25161]: I1012 08:50:54.410793 25161 manager.go:163] Using 192.168.50.102 as external interface
Oct 12 08:50:54 docker4 flanneld[25161]: I1012 08:50:54.411688 25161 manager.go:164] Using 192.168.50.102 as external endpoint
Oct 12 08:50:54 docker4 flanneld[25161]: I1012 08:50:54.423706 25161 local_manager.go:179] **Picking subnet in range 10.100.1.0 ... 10.100.255.0
Oct 12 08:50:54 docker4 flanneld[25161]: I1012 08:50:54.429636 25161 manager.go:246] **Lease acquired: 10.100.15.0/24
Oct 12 08:50:54 docker4 flanneld[25161]: I1012 08:50:54.430507 25161 network.go:98] Watching for new subnet leases
Oct 12 08:50:54 docker4 systemd[1]: **Started Flannel Network Fabric.
user@docker4:/tmp$
```

您应该在日志中看到类似的输出，表明 Flannel 在您配置的`etcd`全局范围分配中找到了一个租约。这些租约对每个主机都是本地的，我经常将它们称为本地范围或网络。下一步是在其余主机上完成此配置。通过检查每个主机上的 Flannel 日志，我可以知道为每个主机分配了哪些子网。在我的情况下，我得到了以下结果：

+   `docker1`：`10.100.93.0/24`

+   `docker2`：`10.100.58.0/24`

+   `docker3`：`10.100.90.0/24`

+   `docker4`：`10.100.15.0/24`

此时，Flannel 已经完全配置好了。在下一个教程中，我们将讨论如何配置 Docker 来使用 Flannel 网络。

# 将 Flannel 与 Docker 集成

正如我们之前提到的，目前 Flannel 和 Docker 之间没有直接集成。也就是说，我们需要找到一种方法将容器放入 Flannel 网络，而 Docker 并不直接知道正在发生的事情。在这个教程中，我们将展示如何做到这一点，讨论导致我们当前配置的一些先决条件，并了解 Flannel 如何处理主机之间的通信。

## 准备工作

假设您正在构建上一个教程中描述的实验室。在某些情况下，我们所做的更改可能需要您具有系统的根级访问权限。

## 如何做到这一点...

在上一个教程中，我们配置了 Flannel，但我们并没有从网络的角度实际检查 Flannel 配置到底做了什么。让我们快速查看一下我们的一个启用了 Flannel 的主机的配置，看看发生了什么变化：

```
user@docker4:~$ ip addr
…<loopback interface removed for brevity>…
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether d2:fe:5e:b2:f6:43 brd ff:ff:ff:ff:ff:ff
    inet 192.168.50.102/24 brd 192.168.50.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::d0fe:5eff:feb2:f643/64 scope link
       valid_lft forever preferred_lft forever
3: flannel0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1472 qdisc pfifo_fast state UNKNOWN group default qlen 500
 link/none
 inet 10.100.15.0/16 scope global flannel0
 valid_lft forever preferred_lft forever
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:16:78:74:cf brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 scope global docker0
       valid_lft forever preferred_lft forever 
user@docker4:~$
```

您会注意到一个名为`flannel0`的新接口的添加。您还会注意到它具有分配给此主机的`/24`本地范围内的 IP 地址。如果我们深入挖掘一下，我们可以使用`ethtool`来确定这个接口是一个虚拟的`tun`接口。

```
user@docker4:~$ ethtool -i flannel0
driver: tun
version: 1.6
firmware-version:
bus-info: tun
supports-statistics: no
supports-test: no
supports-eeprom-access: no
supports-register-dump: no
supports-priv-flags: no
user@docker4:~$
```

Flannel 在运行 Flannel 服务的每个主机上创建了这个接口。请注意，`flannel0`接口的子网掩码是`/16`，它覆盖了我们在`etcd`中定义的整个全局范围分配。尽管为主机分配了`/24`范围，但主机认为整个`/16`都可以通过`flannel0`接口访问：

```
user@docker4:~$ ip route
default via 192.168.50.1 dev eth0
10.100.0.0/16 dev flannel0  proto kernel  scope link  src 10.100.93.0
172.17.0.0/16 dev docker0  proto kernel  scope link  src 172.17.0.1
192.168.50.0/24 dev eth0  proto kernel  scope link  src 192.168.50.102
user@docker4:~$
```

有了接口后，就会创建这条路由，确保前往其他主机上分配的本地范围的流量通过`flannel0`接口。我们可以通过 ping 其他主机上的其他`flannel0`接口来证明这一点：

```
user@docker4:~$ **ping 10.100.93.0 -c 2
PING 10.100.93.0 (10.100.93.0) 56(84) bytes of data.
64 bytes from 10.100.93.0: icmp_seq=1 ttl=62 time=0.901 ms
64 bytes from 10.100.93.0: icmp_seq=2 ttl=62 time=0.930 ms
--- 10.100.93.0 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.901/0.915/0.930/0.033 ms
user@docker4:~$
```

由于物理网络对`10.100.0.0/16`网络空间一无所知，Flannel 必须在流经物理网络时封装流量。为了做到这一点，它需要知道哪个物理 Docker 主机分配了给定的范围。回想一下我们在上一篇示例中检查的 Flannel 日志，Flannel 根据主机的默认路由为每个主机选择了一个外部接口：

```
I0707 09:07:01.733912 02195 main.go:130] **Determining IP address of default interface
I0707 09:07:01.734374 02195 main.go:188] **Using 192.168.50.102 as external interface

```

这些信息以及分配给每个主机的范围都在键值存储中注册。使用这些信息，Flannel 可以确定哪个主机分配了哪个范围，并可以使用该主机的外部接口作为发送封装流量的目的地。

### 注意

Flannel 支持多个后端或传输机制。默认情况下，它会在端口`8285`上使用 UDP 封装流量。在接下来的示例中，我们将讨论其他后端选项。

既然我们知道了 Flannel 的工作原理，我们需要解决如何将实际的 Docker 容器放入 Flannel 网络中。最简单的方法是让 Docker 使用分配的范围作为`docker0`桥接的子网。Flannel 将范围信息写入一个文件，保存在`/run/flannel/subnet.env`中：

```
user@docker4:~$ more /run/flannel/subnet.env
FLANNEL_NETWORK=10.100.0.0/16
FLANNEL_SUBNET=10.100.15.1/24
FLANNEL_MTU=1472
FLANNEL_IPMASQ=false
user@docker4:~$
```

利用这些信息，我们可以配置 Docker 使用正确的子网作为其桥接接口。Flannel 提供了两种方法来实现这一点。第一种方法涉及使用随 Flannel 二进制文件一起提供的脚本生成新的 Docker 配置文件。该脚本允许您输出一个使用`subnet.env`文件中信息的新 Docker 配置文件。例如，我们可以使用该脚本生成一个新的配置，如下所示：

```
user@docker4:~$ cd /tmp
user@docker4:/tmp$ ls
flannel-v0.6.2-linux-amd64.tar.gz  **mk-docker-opts.sh**  README.md  
user@docker4:~/flannel-0.5.5$ ./**mk-docker-opts.sh -c -d \
example_docker_config
user@docker4:/tmp$ more example_docker_config
DOCKER_OPTS=" --bip=10.100.15.1/24 --ip-masq=true --mtu=1472"
user@docker4:/tmp$
```

在不使用`systemd`的系统中，Docker 在大多数情况下会自动检查`/etc/default/docker`文件以获取服务级选项。这意味着我们可以简单地让 Flannel 将前面提到的配置文件写入`/etc/default/docker`，这样当服务重新加载时，Docker 就可以使用新的设置。然而，由于我们的系统使用`systemd`，这种方法需要更新我们的 Docker drop-in 文件(`/etc/systemd/system/docker.service.d/docker.conf`)，使其如下所示：

```
[Service]
EnvironmentFile=**/etc/default/docker
ExecStart=
ExecStart=/usr/bin/dockerd **$DOCKER_OPTS

```

加粗的行表示服务应该检查文件`etc/default/docker`，然后加载变量`$DOCKER_OPTS`以在运行时传递给服务。如果您使用此方法，为了简单起见，定义所有服务级选项都在`etc/default/docker`中可能是明智的。

### 注意：

应该注意的是，这种第一种方法依赖于运行脚本来生成配置文件。如果您手动运行脚本来生成文件，则有可能如果 Flannel 配置更改，配置文件将过时。稍后显示的第二种方法更加动态，因为`/run/flannel/subnet.env`文件由 Flannel 服务更新。

尽管第一种方法当然有效，但我更喜欢使用一个略有不同的方法，我只是从`/run/flannel/subnet.env`文件中加载变量，并在 drop-in 文件中使用它们。为了做到这一点，我们将我们的 Docker drop-in 文件更改为如下所示：

```
[Service]
EnvironmentFile=/run/flannel/subnet.env
ExecStart=
ExecStart=/usr/bin/dockerd --bip=${FLANNEL_SUBNET} --mtu=${FLANNEL_MTU}
```

通过将`/run/flannel/subnet.env`指定为`EnvironmentFile`，我们使文件中定义的变量可供服务定义中使用。然后，我们只需在服务启动时将它们用作选项传递给服务。如果我们在我们的 Docker 主机上进行这些更改，重新加载`systemd`配置，并重新启动 Docker 服务，我们应该看到我们的`docker0`接口现在反映了 Flannel 子网：

```
user@docker4:~$ ip addr show dev docker0
8: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:24:0a:e3:c8 brd ff:ff:ff:ff:ff:ff
    inet **10.100.15.1/24** scope global docker0
       valid_lft forever preferred_lft forever
user@docker4:~$ 
```

您还可以根据 Flannel 配置手动更新 Docker 服务级参数。只需确保您使用`/run/flannel/subnet.env`文件中的信息。无论您选择哪种方法，请确保`docker0`桥在所有四个 Docker 主机上都使用 Flannel 指定的配置。我们的拓扑现在应该是这样的：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_08_02.jpg)

由于每个 Docker 主机只使用其子网的 Flannel 分配范围，因此每个主机都认为全局 Flannel 网络中包含的剩余子网仍然可以通过`flannel0`接口访问。只有分配的本地范围的特定`/24`可以通过`docker0`桥在本地访问：

```
user@docker4:~$ ip route
default via 192.168.50.1 dev eth0 onlink
10.100.0.0/16 dev flannel0**  proto kernel  scope link src 10.100.15.0
10.100.15.0/24 dev docker0**  proto kernel  scope link src 10.100.15.1 
192.168.50.0/24 dev eth0  proto kernel  scope link src 192.168.50.102
user@docker4:~$
```

我们可以通过在两个不同的主机上运行两个不同的容器来验证 Flannel 的操作：

```
user@**docker1**:~$ docker run -dP **--name=web1** jonlangemak/web_server_1
7e44a55c7ea7704d97a8804bfa211344c66f9fb83b3ac17f697c504b3b193e2d
user@**docker1**:~$
user@**docker4**:~$ docker run -dP **--name=web2** jonlangemak/web_server_2
39a47920588b5e0d77ca9d2838988e2d8de893dee6198759f9ddbd3b38cea80d
user@**docker4**:~$
```

现在，我们可以通过 IP 地址直接访问每个容器上运行的服务。首先，找到一个容器的 IP 地址：

```
user@**docker1**:~$ docker exec -it **web1 ip addr show dev eth0
12: eth0@if13: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1472 qdisc noqueue state UP
    link/ether 02:42:0a:64:5d:02 brd ff:ff:ff:ff:ff:ff
    inet **10.100.93.2/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:aff:fe64:5d02/64 scope link
       valid_lft forever preferred_lft forever
user@**docker1**:~$
```

然后，从第二个容器访问服务：

```
user@**docker4**:~$ docker exec -it web2 curl http://**10.100.93.2
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@**docker4**:~$
```

连接正常工作。现在我们已经将整个 Flannel 配置与 Docker 一起工作，重要的是要指出我们做事情的顺序。我们查看的其他解决方案能够将其解决方案的某些部分容器化。例如，Weave 能够以容器格式提供其服务，而不需要像我们使用 Flannel 那样需要本地服务。对于 Flannel，每个组件都有一个先决条件才能工作。

例如，我们需要在 Flannel 注册之前运行`etcd`服务。这本身并不是一个很大的问题，如果`etcd`和 Flannel 都在容器中运行，你可以相当容易地解决这个问题。然而，由于 Docker 需要对其桥接 IP 地址进行的更改是在服务级别完成的，所以 Docker 在启动之前需要知道有关 Flannel 范围的信息。这意味着我们不能在 Docker 容器中运行`etcd`和 Flannel 服务，因为我们无法在没有从`etcd`读取密钥生成的 Flannel 信息的情况下启动 Docker。在这种情况下，了解每个组件的先决条件是很重要的。

### 注意

在 CoreOS 中运行 Flannel 时，他们能够在容器中运行这些组件。解决方案在他们的文档中详细说明了这一点，在*底层*部分的这一行：

[`coreos.com/flannel/docs/latest/flannel-config.html`](https://coreos.com/flannel/docs/latest/flannel-config.html)

# 使用 VXLAN 后端

如前所述，Flannel 支持多种不同的后端配置。后端被认为是 Flannel 在启用 Flannel 的主机之间传递流量的手段。默认情况下，这是通过 UDP 完成的，就像我们在前面的示例中看到的那样。然而，Flannel 也支持 VXLAN。使用 VXLAN 而不是 UDP 的优势在于，较新的主机支持内核中的 VXLAN。在这个示例中，我们将演示如何将 Flannel 后端类型更改为 VXLAN。

## 准备工作

假设您正在构建本章前面示例中描述的实验室。您将需要与 Docker 集成的启用了 Flannel 的主机，就像本章的前两个示例中描述的那样。在某些情况下，我们所做的更改可能需要您具有系统的根级访问权限。

## 如何做…

在你首次在`etcd`中实例化网络时，你希望使用的后端类型是被定义的。由于我们在定义网络`10.100.0.0/16`时没有指定类型，Flannel 默认使用 UDP 后端。这可以通过更新我们最初在`etcd`中设置的配置来改变。回想一下，我们的 Flannel 网络是通过这个命令首次定义的：

```
etcdctl mk /coreos.com/network/config '{"Network":"10.10.0.0/16"}'
```

注意我们如何使用`etcdctl`的`mk`命令来创建键。如果我们想将后端类型更改为 VXLAN，我们可以运行这个命令：

```
etcdctl set /coreos.com/network/config '{"Network":"10.100.0.0/16", "Backend": {"Type": "vxlan"}}'
```

请注意，由于我们正在更新对象，我们现在使用`set`命令代替`mk`。虽然在纯文本形式下有时很难看到，但我们传递给`etcd`的格式正确的 JSON 看起来像这样：

```
{
    "Network": "10.100.0.0/16",
    "Backend": {
        "Type": "vxlan",
    }
}
```

这将定义这个后端的类型为 VXLAN。虽然前面的配置本身足以改变后端类型，但有时我们可以指定作为后端的一部分的额外参数。例如，当将类型定义为 VXLAN 时，我们还可以指定**VXLAN 标识符**（**VNI**）和 UDP 端口。如果未指定，VNI 默认为`1`，端口默认为`8472`。为了演示，我们将默认值作为我们配置的一部分应用：

```
user@docker1:~$ etcdctl set /coreos.com/network/config \
'{"Network":"10.100.0.0/16", "Backend": {"Type": "vxlan","VNI": 1, "Port": 8472}}'
```

这在格式正确的 JSON 中看起来像这样：

```
{
    "Network": "10.100.0.0/16",
    "Backend": {
        "Type": "vxlan",
        "VNI": 1,
        "Port": 8472
    }
}
```

如果我们运行命令，本地`etcd`实例的配置将被更新。我们可以通过`etcdctl`命令行工具查询`etcd`，以验证`etcd`是否具有正确的配置。要读取配置，我们可以使用`etcdctl get`子命令：

```
user@docker1:~$ etcdctl get /coreos.com/network/config
{"Network":"10.100.0.0/16", "Backend": {"Type": "vxlan", "VNI": 1, "Port": 8472}}
user@docker1:~$
```

尽管我们已成功更新了`etcd`，但每个节点上的 Flannel 服务不会根据这个新配置进行操作。这是因为每个主机上的 Flannel 服务只在服务启动时读取这些变量。为了使这个更改生效，我们需要重新启动每个节点上的 Flannel 服务：

```
user@docker4:~$ sudo systemctl restart flanneld
```

确保您重新启动每个主机上的 Flannel 服务。如果有些主机使用 VXLAN 后端，而其他主机使用 UDP 后端，主机将无法通信。重新启动后，我们可以再次检查我们的 Docker 主机的接口：

```
user@docker4:~$ ip addr show
…<Additional output removed for brevity>… 
11: **flannel.1**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN group default
    link/ether 2e:28:e7:34:1a:ff brd ff:ff:ff:ff:ff:ff
    inet **10.100.15.0/16** scope global flannel.1
       valid_lft forever preferred_lft forever
    inet6 fe80::2c28:e7ff:fe34:1aff/64 scope link
       valid_lft forever preferred_lft forever 
```

在这里，我们可以看到主机现在有一个名为`flannel.1`的新接口。如果我们使用`ethtool`检查接口，我们可以看到它正在使用 VXLAN 驱动程序：

```
user@docker4:~$ **ethtool -i flannel.1
driver: **vxlan
version: 0.1
firmware-version:
bus-info:
supports-statistics: no
supports-test: no
supports-eeprom-access: no
supports-register-dump: no
supports-priv-flags: no
user@docker4:~$
```

而且我们应该仍然能够使用 Flannel IP 地址访问服务：

```
user@**docker4**:~$ docker exec -it **web2 curl http://10.100.93.2
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@**docker4**:~$
```

### 注意

如果您指定了不同的 VNI，Flannel 接口将被定义为`flannel.<VNI 编号>`。

重要的是要知道，Flannel 不会清理旧配置的遗留物。例如，如果您更改了`etcd`中的 VXLAN ID 并重新启动 Flannel 服务，您将得到两个接口在同一个网络上。您需要手动删除使用旧 VNI 命名的旧接口。此外，如果更改了分配给 Flannel 的子网，您需要在重新启动 Flannel 服务后重新启动 Docker 服务。请记住，Docker 在加载 Docker 服务时从 Flannel 读取配置变量。如果这些变化，您需要重新加载配置才能生效。

# 使用主机网关后端

正如我们已经看到的，Flannel 支持两种类型的覆盖网络。使用 UDP 或 VXLAN 封装，Flannel 可以在 Docker 主机之间构建覆盖网络。这样做的明显优势是，您可以在不触及物理底层网络的情况下，在不同的 Docker 节点之间提供网络。然而，某些类型的覆盖网络也会引入显著的性能惩罚，特别是对于在用户空间执行封装的进程。主机网关模式旨在通过不使用覆盖网络来解决这个问题。然而，这也带来了自己的限制。在这个示例中，我们将回顾主机网关模式可以提供什么，并展示如何配置它。

## 准备工作

在这个示例中，我们将稍微修改我们一直在使用的实验室。实验室拓扑将如下所示：

![准备工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_08_03.jpg)

在这种情况下，主机`docker3`和`docker4`现在具有与`docker1`和`docker2`相同子网的 IP 地址。也就是说，所有主机现在都是相互的二层邻接，并且可以直接通信，无需通过网关进行路由。一旦您将主机在此拓扑中重新配置，我们将希望清除 Flannel 配置。要做到这一点，请执行以下步骤：

+   在运行`etcd`服务的主机上：

```
sudo systemctl stop etcd
sudo rm -rf /var/lib/etcd/default 
sudo systemctl start etcd
```

+   在所有运行 Flannel 服务的主机上：

```
sudo systemctl stop flanneld
sudo ip link delete flannel.1
sudo systemctl --no-block start flanneld
```

### 注意

您会注意到我们在启动`flanneld`时传递了`systemctl`命令和`--no-block`参数。由于我们从`etcd`中删除了 Flannel 配置，Flannel 服务正在搜索用于初始化的配置。由于服务的定义方式（类型为通知），传递此参数是必需的，以防止命令在 CLI 上挂起。

## 如何做…

此时，您的 Flannel 节点将正在搜索其配置。由于我们删除了`etcd`数据存储，目前缺少告诉 Flannel 节点如何配置服务的密钥，Flannel 服务将继续轮询`etcd`主机，直到我们进行适当的配置。我们可以通过检查其中一个主机的日志来验证这一点：

```
user@docker4:~$ journalctl -f -u flanneld
-- Logs begin at Wed 2016-10-12 12:39:35 CDT. –
Oct 12 12:39:36 docker4 flanneld[873]: I1012 12:39:36.843784 00873 manager.go:163] **Using 10.10.10.104 as external interface
Oct 12 12:39:36 docker4 flanneld[873]: I1012 12:39:36.844160 00873 manager.go:164] **Using 10.10.10.104 as external endpoint
Oct 12 12:41:22 docker4 flanneld[873]: E1012 12:41:22.102872 00873 network.go:106] **failed to retrieve network config: 100: Key not found (/coreos.com)** [4]
Oct 12 12:41:23 docker4 flanneld[873]: E1012 12:41:23.104904 00873 network.go:106] **failed to retrieve network config: 100: Key not found (/coreos.com)** [4] 
```

重要的是要注意，此时 Flannel 已经通过查看哪个接口支持主机的默认路由来决定其外部端点 IP 地址：

```
user@docker4:~$ ip route
default via 10.10.10.1 dev eth0
10.10.10.0/24 dev eth0  proto kernel  scope link  src 10.10.10.104
user@docker4:~$
```

由于这恰好是`eth0`，Flannel 选择该接口的 IP 地址作为其外部地址。要配置主机网关模式，我们可以将以下配置放入`etcd`：

```
{  
   "Network":"10.100.0.0/16",
   "Backend":{  
      "Type":"host-gw"
   }
}
```

正如我们以前看到的，我们仍然指定一个网络。唯一的区别是我们提供了`type`为`host-gw`。将其插入`etcd`的命令如下：

```
user@docker1:~$ etcdctl set /coreos.com/network/config \
'{"Network":"10.100.0.0/16", "Backend": {"Type": "host-gw"}}'
```

在我们插入此配置后，Flannel 节点应该都会接收到新的配置。让我们检查主机`docker4`上 Flannel 的服务日志以验证这一点：

```
user@docker4:~$ journalctl -r -u flanneld
-- Logs begin at Wed 2016-10-12 12:39:35 CDT, end at Wed 2016-10-12 12:55:38 CDT. --
Oct 12 12:55:06 docker4 flanneld[873]: I1012 12:55:06.797289 00873 network.go:83] **Subnet added: 10.100.23.0/24 via 10.10.10.103
Oct 12 12:55:06 docker4 flanneld[873]: I1012 12:55:06.796982 00873 network.go:83] **Subnet added: 10.100.20.0/24 via 10.10.10.101
Oct 12 12:55:06 docker4 flanneld[873]: I1012 12:55:06.796468 00873 network.go:83] **Subnet added: 10.100.43.0/24 via 10.10.10.102
Oct 12 12:55:06 docker4 flanneld[873]: I1012 12:55:06.785464 00873 network.go:51] **Watching for new subnet leases
Oct 12 12:55:06 docker4 flanneld[873]: I1012 12:55:06.784436 00873 manager.go:246] **Lease acquired: 10.100.3.0/24
Oct 12 12:55:06 docker4 flanneld[873]: I1012 12:55:06.779349 00873 local_manager.go:179] **Picking subnet in range 10.100.1.0 ... 10.100.255.0

```

### 注意

`journalctl`命令对于查看由`systemd`管理的服务的所有日志非常有用。在前面的示例中，我们传递了`-r`参数以倒序显示日志（最新的在顶部）。我们还传递了`-u`参数以指定我们要查看日志的服务。

我们看到的最旧的日志条目是这个主机的 Flannel 服务在`10.100.0.0/16`子网内选择并注册范围。这与 UDP 和 VXLAN 后端的工作方式相同。接下来的三个日志条目显示 Flannel 检测到其他三个 Flannel 节点范围的注册。由于`etcd`正在跟踪每个 Flannel 节点的外部 IP 地址，以及它们注册的范围，所有 Flannel 主机现在都知道可以用什么外部 IP 地址来到达每个注册的 Flannel 范围。在覆盖模式（UDP 或 VXLAN）中，此外部 IP 地址被用作封装流量的目的地。在主机网关模式中，此外部 IP 地址被用作路由目的地。如果我们检查路由表，我们可以看到每个主机的路由条目：

```
user@docker4:~$ ip route
default via 10.10.10.1 dev eth0 onlink
10.10.10.0/24 dev eth0  proto kernel  scope link  src 10.10.10.104
10.100.20.0/24 via 10.10.10.101 dev eth0
10.100.23.0/24 via 10.10.10.103 dev eth0
10.100.43.0/24 via 10.10.10.102 dev eth0
user@docker4:~$
```

在这种配置中，Flannel 只是依赖基本路由来提供对所有 Flannel 注册范围的可达性。在这种情况下，主机`docker4`有路由到所有其他 Docker 主机的路由，以便到达它们的 Flannel 网络范围：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_08_04.jpg)

这不仅比处理覆盖网络要简单得多，而且比要求每个主机为覆盖网络进行封装要更高效。这种方法的缺点是每个主机都需要在同一网络上有一个接口才能正常工作。如果主机不在同一网络上，Flannel 无法添加这些路由，因为这将需要上游网络设备（主机的默认网关）也具有有关如何到达远程主机的路由信息。虽然 Flannel 节点可以在其默认网关上指定静态路由，但物理网络对`10.100.0.0/16`网络一无所知，并且无法传递流量。其结果是主机网关模式限制了您可以放置启用 Flannel 的 Docker 主机的位置。

最后，重要的是要指出，Flannel 在 Docker 服务已经运行后可能已经改变状态。如果是这种情况，您需要重新启动 Docker，以确保它从 Flannel 中获取新的变量。如果在重新配置网络接口时重新启动了主机，则可能只需要启动 Docker 服务。系统启动时，服务可能因缺少 Flannel 配置信息而未能加载，现在应该已经存在。

### 注意

Flannel 还为各种云提供商（如 GCE 和 AWS）提供了后端。您可以查看它们的文档，以获取有关这些后端类型的更多具体信息。

# 指定 Flannel 选项

除了配置不同的后端类型，您还可以通过`etcd`和 Flannel 客户端本身指定其他选项。这些选项允许您限制 IP 分配范围，并指定用作 Flannel 节点外部 IP 端点的特定接口。在本教程中，我们将审查您在本地和全局都可以使用的其他配置选项。

## 做好准备

我们将继续构建上一章中的实验，在那里我们配置了主机网关后端。但是，实验拓扑将恢复到以前的配置，其中 Docker 主机`docker3`和`docker4`位于`192.168.50.0/24`子网中：

![做好准备](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_08_05.jpg)

一旦您在这个拓扑中配置了您的主机，我们将想要清除 Flannel 配置。为此，请执行以下步骤：

+   在运行`etcd`服务的主机上：

```
sudo systemctl stop etcd
sudo rm -rf /var/lib/etcd/default 
sudo systemctl start etcd
```

+   在所有运行 Flannel 服务的主机上：

```
sudo systemctl stop flanneld
sudo ip link delete flannel.1
sudo systemctl --no-block start flanneld
```

在某些情况下，我们所做的更改可能需要您具有系统的根级访问权限。

## 如何做…

之前的示例展示了如何指定整体 Flannel 网络或全局范围，并改变后端网络类型。我们还看到一些后端网络类型允许额外的配置选项。除了我们已经看到的选项之外，我们还可以全局配置其他参数，来决定 Flannel 的整体工作方式。有三个其他主要参数可以影响分配给 Flannel 节点的范围：

+   `SubnetLen`: 此参数以整数形式指定，并规定了分配给每个节点的范围的大小。正如我们所见，这默认为`/24`

+   `SubnetMin`: 此参数以字符串形式指定，并规定了范围分配应该开始的起始 IP 范围

+   `SubnetMax`: 此参数以字符串形式指定，并规定了子网分配应该结束的 IP 范围的末端

将这些选项与`Network`标志结合使用时，我们在分配网络时具有相当大的灵活性。例如，让我们使用这个配置：

```
{  
   "Network":"10.100.0.0/16",
   "SubnetLen":25,
   "SubnetMin":"10.100.0.0",
   "SubnetMax":"10.100.1.0",
   "Backend":{  
      "Type":"host-gw"
   }
}
```

这定义了每个 Flannel 节点应该获得一个`/25`的范围分配，第一个子网应该从`10.100.0.0`开始，最后一个子网应该结束于`10.100.1.0`。您可能已经注意到，在这种情况下，我们只有空间来容纳三个子网：

+   `10.100.0.0/25`

+   `10.100.0.128./25`

+   `10.100.1.0/25`

这是故意为了展示当 Flannel 在全局范围内空间不足时会发生什么。现在让我们使用这个命令将这个配置放入`etcd`中：

```
user@docker1:~$ etcdctl set /coreos.com/network/config \
 '{"Network":"10.100.0.0/16","SubnetLen": 25, "SubnetMin": "10.100.0.0", "SubnetMax": "10.100.1.0", "Backend": {"Type": "host-gw"}}'
```

一旦放置，您应该会看到大多数主机接收到本地范围的分配。但是，如果我们检查我们的主机，我们会发现有一个主机未能接收到分配。在我的情况下，那就是主机`docker4`。我们可以在 Flannel 服务的日志中看到这一点：

```
user@docker4:~$ journalctl -r -u flanneld
-- Logs begin at Wed 2016-10-12 12:39:35 CDT, end at Wed 2016-10-12 13:17:42 CDT. --
Oct 12 13:17:42 docker4 flanneld[1422]: E1012 13:17:42.650086 01422 network.go:106] **failed to register network: failed to acquire lease: out of subnets
Oct 12 13:17:42 docker4 flanneld[1422]: I1012 13:17:42.649604 01422 local_manager.go:179] Picking subnet in range 10.100.0.0 ... 10.100.1.0
```

由于我们在全局范围内只允许了三个分配空间，第四个主机无法接收本地范围，并将继续请求，直到有一个可用。这可以通过更新`SubnetMax`参数为`10.100.1.128`并重新启动未能接收本地范围分配的主机上的 Flannel 服务来解决。

正如我所提到的，我们还可以将配置参数传递给每个主机上的 Flannel 服务。

### 注意

Flannel 客户端支持各种参数，所有这些参数都可以通过运行`flanneld --help`来查看。这些参数涵盖了新的和即将推出的功能，以及与基于 SSL 的通信相关的配置，在在运行这些类型的服务时，这些配置将是重要的。

从网络的角度来看，也许最有价值的配置选项是`--iface`参数，它允许您指定要用作 Flannel 外部端点的主机接口。为了了解其重要性，让我们看一个我们的多主机实验室拓扑的快速示例：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_08_06.jpg)

如果你还记得，在主机网关模式下，Flannel 要求所有 Flannel 节点都是二层相邻的，或者在同一个网络上。在这种情况下，左侧有两个主机在`10.10.10.0/24`网络上，右侧有两个主机在`192.168.50.0/24`网络上。为了彼此通信，它们需要通过多层交换机进行路由。这种情况通常需要一个覆盖后端模式，可以通过多层交换机隧道传输容器流量。然而，如果主机网关模式是性能或其他原因的要求，如果您可以为主机提供额外的接口，您可能仍然可以使用它。例如，想象一下，这些主机实际上是虚拟机，相对容易为我们在每个主机上提供另一个接口，称之为`eth1`：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/B05453_08_07.jpg)

这个接口可以专门用于 Flannel 流量，允许每个主机仍然在 Flannel 流量的情况下保持二层相邻，同时保持它们通过`eth0`的现有默认路由。然而，仅仅配置接口是不够的。请记住，Flannel 默认通过引用主机的默认路由来选择其外部端点接口。由于在这种模型中默认路由没有改变，Flannel 将无法添加适当的路由：

```
user@docker4:~$ journalctl -ru flanneld
-- Logs begin at Wed 2016-10-12 14:24:51 CDT, end at Wed 2016-10-12 14:31:14 CDT. --
Oct 12 14:31:14 docker4 flanneld[1491]: E1012 14:31:14.463106 01491 network.go:116] **Error adding route to 10.100.1.128/25 via 10.10.10.102: network is unreachable
Oct 12 14:31:14 docker4 flanneld[1491]: I1012 14:31:14.462801 01491 network.go:83] Subnet added: 10.100.1.128/25 via 10.10.10.102
Oct 12 14:31:14 docker4 flanneld[1491]: E1012 14:31:14.462589 01491 network.go:116] **Error adding route to 10.100.0.128/25 via 10.10.10.101: network is unreachable
Oct 12 14:31:14 docker4 flanneld[1491]: I1012 14:31:14.462008 01491 network.go:83] Subnet added: 10.100.0.128/25 via 10.10.10.101
```

由于 Flannel 仍然使用`eth0`接口作为其外部端点 IP 地址，它知道另一个子网上的主机是无法直接到达的。我们可以通过向 Flannel 服务传递`--iface`选项来告诉 Flannel 使用`eth1`接口来解决这个问题。

例如，我们可以通过更新 Flannel 服务定义（`/lib/systemd/system/flanneld.service`）来更改 Flannel 配置，使其如下所示：

```
[Unit]
Description=Flannel Network Fabric
Documentation=https://github.com/coreos/flannel
Before=docker.service
After=etcd.service

[Service]
Environment= 'DAEMON_ARGS=--etcd-endpoints=http://10.10.10.101:2379 **--iface=eth1'
Type=notify
ExecStart=/usr/bin/flanneld $DAEMON_ARGS
Restart=always
RestartSec=10s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

有了这个配置，Flannel 将使用`eth1`接口作为其外部端点，从而使所有主机能够直接在`10.11.12.0/24`网络上进行通信。然后，您可以通过重新加载`systemd`配置并在所有主机上重新启动服务来加载新配置：

```
sudo systemctl daemon-reload
sudo systemctl restart flanneld
```

请记住，Flannel 使用外部端点 IP 地址来跟踪 Flannel 节点。更改这意味着 Flannel 将为每个 Flannel 节点分配一个新的范围。最好在加入 Flannel 节点之前配置这些选项。在我们的情况下，由于`etcd`已经配置好，我们将再次删除现有的`etcd`配置，并重新配置它，以便范围变得可用。

```
user@docker1:~$ sudo systemctl stop etcd
user@docker1:~$ sudo rm -rf /var/lib/etcd/default
user@docker1:~$ sudo systemctl start etcd
user@docker1:~$ etcdctl set /coreos.com/network/config \
 '{"Network":"10.100.0.0/16","SubnetLen": 25, "SubnetMin": "10.100.0.0", "SubnetMax": "10.100.1.128", "Backend": {"Type": "host-gw"}}'
```

如果您检查主机，现在应该看到它有三个 Flannel 路由——每个路由对应其他三个主机的分配范围之一：

```
user@docker1:~$ ip route
default via 10.10.10.1 dev eth0 onlink
10.10.10.0/24 dev eth0  proto kernel  scope link src 10.10.10.101
10.11.12.0/24 dev eth1  proto kernel  scope link src 10.11.12.101
10.100.0.0/25 via 10.11.12.102 dev eth1
10.100.1.0/25 via 10.11.12.104 dev eth1
10.100.1.128/25 via 10.11.12.103 dev eth1
10.100.0.128/25 dev docker0  proto kernel  scope link src 10.100.75.1 
user@docker1:~$
```

此外，如果您将通过 NAT 使用 Flannel，您可能还想查看`--public-ip`选项，该选项允许您定义节点的公共 IP 地址。这在云环境中尤为重要，因为服务器的真实 IP 地址可能被隐藏在 NAT 后面。


# 第九章：探索网络功能

在本章中，我们将涵盖以下内容：

+   使用 Docker 的预发布版本

+   理解 MacVLAN 接口

+   使用 Docker MacVLAN 网络驱动程序

+   理解 IPVLAN 接口

+   使用 Docker IPVLAN 网络驱动程序

+   使用 MacVLAN 和 IPVLAN 网络标记 VLAN ID

# 介绍

尽管我们在前几章讨论过的许多功能自从一开始就存在，但许多功能是最近才引入的。Docker 是一个快速发展的开源软件，有许多贡献者。为了管理功能的引入、测试和潜在发布，Docker 以几种不同的方式发布代码。在本章中，我们将展示如何探索尚未包含在软件生产或发布版本中的功能。作为其中的一部分，我们将回顾 Docker 引入的两个较新的网络功能。其中一个是 MacVLAN，最近已经合并到软件的发布版本中，版本号为 1.12。第二个是 IPVLAN，仍然处于预发布软件渠道中。在我们回顾如何使用 Docker 预发布软件渠道之后，我们将讨论 MacVLAN 和 IPVLAN 网络接口的基本操作，然后讨论它们在 Docker 中作为驱动程序的实现方式。

# 使用 Docker 的预发布版本

Docker 提供了两种不同的渠道，您可以在其中预览未发布的代码。这使用户有机会审查既定发布的功能，也可以审查完全实验性的功能，这些功能可能永远不会进入实际发布版本。审查这些功能并对其提供反馈是开源软件开发的重要组成部分。Docker 认真对待收到的反馈，许多在这些渠道中测试过的好主意最终会进入生产代码发布中。在本篇中，我们将回顾如何安装测试和实验性的 Docker 版本。

## 准备工作

在本教程中，我们将使用一个新安装的 Ubuntu 16.04 主机。虽然这不是必需的，但建议您在当前未安装 Docker 的主机上安装 Docker 的预发布版本。如果安装程序检测到 Docker 已经安装，它将警告您不要安装实验或测试代码。也就是说，我建议在专用的开发服务器上进行来自这些渠道的软件测试。在许多情况下，虚拟机用于此目的。如果您使用虚拟机，我建议您安装基本操作系统，然后对 VM 进行快照，以便为自己创建还原点。如果安装出现问题，您可以始终恢复到此快照以从已知良好的系统开始。

正如 Docker 在其文档中所指出的：

> *实验性功能尚未准备好投入生产。它们提供给您在沙盒环境中进行测试和评估。*

请在使用非生产代码的任何一列火车时牢记这一点。强烈建议您在 GitHub 上就任何渠道中存在的所有功能提供反馈。

## 如何做…

如前所述，终端用户可以使用两个不同的预发布软件渠道。

+   [`experimental.docker.com/`](https://experimental.docker.com/)：这是下载和安装 Docker 实验版本的脚本的 URL。该版本包括完全实验性的功能。其中许多功能可能在以后的某个时候集成到生产版本中。然而，许多功能不会这样做，而是仅用于实验目的。

+   [`test.docker.com/`](https://test.docker.com/)：这是下载和安装 Docker 测试版本的脚本的 URL。Docker 还将其称为**发布候选**（**RC**）版本的代码。这些代码具有计划发布但尚未集成到 Docker 生产或发布版本中的功能。

要安装任一版本，您只需从 URL 下载脚本并将其传递给 shell。例如：

+   要安装实验版，请运行此命令：

```
curl -sSL https://experimental.docker.com/ | sh
```

+   要安装测试版或候选发布版，请运行此命令：

```
curl -sSL https://test.docker.com/ | sh
```

### 注意

值得一提的是，您也可以使用类似的配置来下载 Docker 的生产版本。除了[`test.docker.com/`](https://test.docker.com/)和[`experimental.docker.com/`](https://experimental.docker.com/)之外，还有[`get.docker.com/`](https://get.docker.com/)，它将安装软件的生产版本。

如前所述，这些脚本的使用应该在当前未安装 Docker 的机器上进行。安装后，您可以通过检查`docker info`的输出来验证是否安装了适当的版本。例如，在安装实验版本时，您可以在输出中看到实验标志已设置：

```
user@docker-test:~$ sudo docker info
Containers: 0
 Running: 0
 Paused: 0
 Stopped: 0
Images: 0
Server Version: 1.12.2
…<Additional output removed for brevity>…
Experimental: true
Insecure Registries:
 127.0.0.0/8
user@docker-test:~$
```

在测试或 RC 版本中，您将看到类似的输出；但是，在 Docker info 的输出中不会列出实验变量：

```
user@docker-test:~$ sudo docker info
Containers: 0
 Running: 0
 Paused: 0
 Stopped: 0
Images: 0
Server Version: 1.12.2-rc3
…<Additional output removed for brevity>…
Insecure Registries:
 127.0.0.0/8
user@docker-test:~$
```

通过脚本安装后，您会发现 Docker 已安装并运行，就好像您通过操作系统的默认软件包管理器安装了 Docker 一样。虽然脚本应该在安装的最后提示您，但建议将您的用户帐户添加到 Docker 组中。这样可以避免您在使用 Docker CLI 命令时需要提升权限使用`sudo`。要将您的用户帐户添加到 Docker 组中，请使用以下命令：

```
user@docker-test:~$ sudo usermod -aG docker <your username>
```

确保您注销并重新登录以使设置生效。

请记住，这些脚本也可以用于更新任一渠道的最新版本。在这些情况下，脚本仍会提示您有关在现有 Docker 安装上安装的可能性，但它将提供措辞以指示您可以忽略该消息：

```
user@docker-test:~$ **curl -sSL https://test.docker.com/ | sh
Warning: the "docker" command appears to already exist on this system.

If you already have Docker installed, this script can cause trouble, which is why we're displaying this warning and provide the opportunity to cancel the installation.

If you installed the current Docker package using this script and are using it again to update Docker, you can safely ignore this message.

You may press Ctrl+C now to abort this script.
+ sleep 20
```

虽然这不是获取测试和实验代码的唯一方法，但肯定是最简单的方法。您也可以下载预构建的二进制文件或自行构建二进制文件。有关如何执行这两种操作的信息可在 Docker 的 GitHub 页面上找到：[`github.com/docker/docker/tree/master/experimental`](https://github.com/docker/docker/tree/master/experimental)。

# 理解 MacVLAN 接口

我们将要看的第一个特性是 MacVLAN。在这个教程中，我们将在 Docker 之外实现 MacVLAN，以更好地理解它的工作原理。了解 Docker 之外的 MacVLAN 如何工作对于理解 Docker 如何使用 MacVLAN 至关重要。在下一个教程中，我们将介绍 Docker 网络驱动程序对 MacVLAN 的实现。

## 准备工作

在这个示例中，我们将使用两台 Linux 主机（`net1`和`net2`）来演示 MacVLAN 功能。我们的实验室拓扑将如下所示：

![准备就绪](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_01.jpg)

假设主机处于基本配置状态，每台主机都有两个网络接口。 `eth0`接口将有一个静态 IP 地址，并作为每个主机的默认网关。 `eth1`接口将配置为没有 IP 地址。 供参考，您可以在每个主机的网络配置文件（`/etc/network/interfaces`）中找到以下内容：

+   `net1.lab.lab`

```
auto eth0
iface eth0 inet static
        address 172.16.10.2
        netmask 255.255.255.0
        gateway 172.16.10.1
        dns-nameservers 10.20.30.13
        dns-search lab.lab

auto eth1
iface eth1 inet manual
```

+   `net2.lab.lab`

```
auto eth0
iface eth0 inet static
        address 172.16.10.3
        netmask 255.255.255.0
        gateway 172.16.10.1
        dns-nameservers 10.20.30.13
        dns-search lab.lab

auto eth1
iface eth1 inet manual
```

### 注意

虽然我们将在这个示例中涵盖创建拓扑所需的所有步骤，但如果有些步骤不清楚，您可能希望参考第一章, *Linux 网络构造*。第一章, *Linux 网络构造*，更深入地介绍了基本的 Linux 网络构造和 CLI 工具。

## 如何操作…

MacVLAN 代表一种完全不同的接口配置方式，与我们到目前为止所见过的方式完全不同。我们之前检查的 Linux 网络配置依赖于松散模仿物理网络结构的构造。MacVLAN 接口在逻辑上是绑定到现有网络接口的，并且被称为**父**接口，可以支持一个或多个 MacVLAN 逻辑接口。让我们快速看一下在我们的实验室主机上配置 MacVLAN 接口的一个示例。

配置 MacVLAN 类型接口的方式与 Linux 网络接口上的所有其他类型非常相似。使用`ip`命令行工具，我们可以使用`link`子命令来定义接口：

```
user@net1:~$ sudo ip link add macvlan1 link eth0 type macvlan 
```

这个语法应该对你来说很熟悉，因为我们在书的第一章中定义了多种不同的接口类型。创建后，下一步是为其配置 IP 地址。这也是通过`ip`命令完成的：

```
user@net1:~$ sudo ip address add 172.16.10.5/24 dev macvlan1

```

最后，我们需要确保启动接口。

```
user@net1:~$ sudo ip link set dev macvlan1 up
```

接口现在已经启动，我们可以使用`ip addr show`命令来检查配置：

```
user@net1:~$ ip addr show
1: …<loopback interface configuration removed for brevity>…
2: **eth0**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:2d:dd:79 brd ff:ff:ff:ff:ff:ff
    inet **172.16.10.2/24** brd 172.16.10.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:fe2d:dd79/64 scope link
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:2d:dd:83 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::20c:29ff:fe2d:dd83/64 scope link
       valid_lft forever preferred_lft forever
4: **macvlan1@eth0**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default
    link/ether da:aa:c0:18:55:4a brd ff:ff:ff:ff:ff:ff
    inet **172.16.10.5/24** scope global macvlan1
       valid_lft forever preferred_lft forever
    inet6 fe80::d8aa:c0ff:fe18:554a/64 scope link
       valid_lft forever preferred_lft forever
user@net1:~$
```

现在我们已经配置了接口，有几个有趣的地方需要指出。首先，MacVLAN 接口的名称使得很容易识别接口的父接口。回想一下，我们提到每个 MacVLAN 接口都必须与一个父接口关联。在这种情况下，我们可以通过查看 MacVLAN 接口名称中`macvlan1@`后面列出的名称来知道这个 MacVLAN 接口的父接口是`eth0`。其次，分配给 MacVLAN 接口的 IP 地址与父接口（`eth0`）处于相同的子网中。这是有意为之，以允许外部连接。让我们在同一个父接口上定义第二个 MacVLAN 接口，以演示允许的连接性：

```
user@net1:~$ sudo ip link add macvlan2 link eth0 type macvlan
user@net1:~$ sudo ip address add 172.16.10.6/24 dev macvlan2
user@net1:~$ sudo ip link set dev macvlan2 up
```

我们的网络拓扑如下：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_02.jpg)

我们有两个 MacVLAN 接口绑定到 net1 的`eth0`接口。如果我们尝试从外部子网访问任一接口，连接性应该如预期般工作：

```
user@test_server:~$** ip addr show dev **eth0** |grep inet
    inet **10.20.30.13/24** brd 10.20.30.255 scope global eth0
user@test_server:~$ ping 172.16.10.5 -c 2
PING 172.16.10.5 (172.16.10.5) 56(84) bytes of data.
64 bytes from 172.16.10.5: icmp_seq=1 ttl=63 time=0.423 ms
64 bytes from 172.16.10.5: icmp_seq=2 ttl=63 time=0.458 ms
--- 172.16.10.5 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1000ms
rtt min/avg/max/mdev = 0.423/0.440/0.458/0.027 ms
user@test_server:~$ ping 172.16.10.6 -c 2
PING 172.16.10.6 (172.16.10.6) 56(84) bytes of data.
64 bytes from 172.16.10.6: icmp_seq=1 ttl=63 time=0.510 ms
64 bytes from 172.16.10.6: icmp_seq=2 ttl=63 time=0.532 ms
--- 172.16.10.6 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1000ms
rtt min/avg/max/mdev = 0.510/0.521/0.532/0.011 ms
```

在前面的输出中，我尝试从`net1`主机的子网外部的测试服务器上到达`172.16.10.5`和`172.16.10.6`。在这两种情况下，我们都能够到达 MacVLAN 接口的 IP 地址，这意味着路由正在按预期工作。这就是为什么我们给 MacVLAN 接口分配了服务器`eth0`接口现有子网内的 IP 地址。由于多层交换机知道`172.16.10.0/24`位于 VLAN 10 之外，它只需为 VLAN 10 上的新 IP 地址发出 ARP 请求，以获取它们的 MAC 地址。Linux 主机已经有一个指向允许返回流量到达测试服务器的交换机的默认路由。然而，这绝不是 MacVLAN 接口的要求。我本可以轻松选择另一个 IP 子网用于接口，但那将阻止外部路由的固有工作。

另一个需要指出的地方是父接口不需要有关联的 IP 地址。例如，让我们通过在主机`net1`上建立两个更多的 MacVLAN 接口来扩展拓扑。一个在主机`net1`上，另一个在主机`net2`上：

```
user@net1:~$ sudo ip link add macvlan3 link eth1 type macvlan
user@net1:~$ sudo ip address add 192.168.10.5/24 dev macvlan3
user@net1:~$ sudo ip link set dev macvlan3 up

user@net2:~$ sudo ip link add macvlan4 link eth1 type macvlan
user@net2:~$ sudo ip address add 192.168.10.6/24 dev macvlan4
user@net2:~$ sudo ip link set dev macvlan4 up
```

我们的拓扑如下：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_03.jpg)

尽管在物理接口上没有定义 IP 地址，但主机现在将`192.168.10.0/24`网络视为已定义，并认为该网络是本地连接的：

```
user@net1:~$ ip route
default via 172.16.10.1 dev eth0
172.16.10.0/24 dev eth0  proto kernel  scope link  src 172.16.10.2
172.16.10.0/24 dev macvlan1  proto kernel  scope link  src 172.16.10.5
172.16.10.0/24 dev macvlan2  proto kernel  scope link  src 172.16.10.6
192.168.10.0/24 dev macvlan3  proto kernel  scope link  src 192.168.10.5
user@net1:~$
```

这意味着两个主机可以直接通过它们在该子网上的关联 IP 地址相互到达：

```
user@**net1**:~$ ping **192.168.10.6** -c 2
PING 192.168.10.6 (192.168.10.6) 56(84) bytes of data.
64 bytes from 192.168.10.6: icmp_seq=1 ttl=64 time=0.405 ms
64 bytes from 192.168.10.6: icmp_seq=2 ttl=64 time=0.432 ms
--- 192.168.10.6 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1000ms
rtt min/avg/max/mdev = 0.405/0.418/0.432/0.024 ms
user@net1:~$
```

此时，您可能会想知道为什么要使用 MacVLAN 接口类型。从外观上看，它似乎与创建逻辑子接口没有太大区别。真正的区别在于接口的构建方式。通常，子接口都使用相同的父接口的 MAC 地址。您可能已经注意到在先前的输出和图表中，MacVLAN 接口具有与其关联的父接口不同的 MAC 地址。我们也可以在上游多层交换机（网关）上验证这一点：

```
switch# show ip arp vlan 10
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  172.16.10.6             8   a2b1.0cd4.4e73  ARPA   Vlan10
Internet  172.16.10.5             8   4e19.f07f.33e0  ARPA   Vlan10
Internet  172.16.10.2             0   000c.292d.dd79  ARPA   Vlan10
Internet  172.16.10.3            62   000c.2959.caca  ARPA   Vlan10
Internet  172.16.10.1             -   0021.d7c5.f245  ARPA   Vlan10
```

### 注意

在测试中，您可能会发现 Linux 主机对于配置中的每个 IP 地址都呈现相同的 MAC 地址。根据您运行的操作系统，您可能需要更改以下内核参数，以防止主机呈现相同的 MAC 地址：

```
echo 1 | sudo tee /proc/sys/net/ipv4/conf/all/arp_ignore
echo 2 | sudo tee /proc/sys/net/ipv4/conf/all/arp_announce
echo 2 | sudo tee /proc/sys/net/ipv4/conf/all/rp_filter
```

请记住，以这种方式应用这些设置不会在重新启动后持久存在。

从 MAC 地址来看，我们可以看到父接口（`172.16.10.2`）和两个 MacVLAN 接口（`172.16.10.5`和`6`）具有不同的 MAC 地址。MacVLAN 允许您使用不同的 MAC 地址呈现多个接口。其结果是您可以拥有多个 IP 接口，每个接口都有自己独特的 MAC 地址，但都使用同一个物理接口。

由于父接口负责多个 MAC 地址，它需要处于混杂模式。当选择为父接口时，主机应自动将接口置于混杂模式。您可以通过检查 ip 链接详细信息来验证：

```
user@net2:~$ ip -d link
…<output removed for brevity>…
2: **eth1**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:59:ca:d4 brd ff:ff:ff:ff:ff:ff **promiscuity 1
…<output removed for brevity>…
```

### 注意

如果父接口处于混杂模式是一个问题，您可能会对本章后面讨论的 IPVLAN 配置感兴趣。

与我们见过的其他 Linux 接口类型一样，MacVLAN 接口也支持命名空间。这可以导致一些有趣的配置选项。现在让我们来看看如何在独立的网络命名空间中部署 MacVLAN 接口。

让我们首先删除所有现有的 MacVLAN 接口：

```
user@net1:~$ sudo ip link del macvlan1
user@net1:~$ sudo ip link del macvlan2
user@net1:~$ sudo ip link del macvlan3
user@net2:~$ sudo ip link del macvlan4
```

就像我们在第一章中所做的那样，*Linux 网络构造*，我们可以创建一个接口，然后将其移入一个命名空间。我们首先创建命名空间：

```
user@net1:~$ sudo ip netns add namespace1
```

然后，我们创建 MacVLAN 接口：

```
user@net1:~$ sudo ip link add macvlan1 link eth0 type macvlan
```

接下来，我们将接口移入新创建的网络命名空间：

```
user@net1:~$ sudo ip link set macvlan1 netns namespace1
```

最后，从命名空间内部，我们为其分配一个 IP 地址并将其启动：

```
user@net1:~$ sudo ip netns exec namespace1 ip address \
add 172.16.10.5/24 dev macvlan1
user@net1:~$ sudo ip netns exec namespace1 ip link set \
dev macvlan1 up
```

让我们也在第二个命名空间中创建一个第二个接口，用于测试目的：

```
user@net1:~$ sudo ip netns add namespace2
user@net1:~$ sudo ip link add macvlan2 link eth0 type macvlan
user@net1:~$ sudo ip link set macvlan2 netns namespace2
user@net1:~$ sudo ip netns exec namespace2 ip address \
add 172.16.10.6/24 dev macvlan2
user@net1:~$ sudo ip netns exec namespace2 ip link set \
dev macvlan2 up
```

### 注意

当您尝试不同的配置时，通常会多次创建和删除相同的接口。这样做时，您可能会生成具有相同 IP 地址但不同 MAC 地址的接口。由于我们将这些 MAC 地址呈现给上游物理网络，因此请务必确保上游设备或网关具有要到达的 IP 的最新 ARP 条目。许多交换机和路由器在长时间内不会为新的 MAC 条目 ARP 而具有长的 ARP 超时值是很常见的。

此时，我们的拓扑看起来是这样的：

![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_04.jpg)

父接口（`eth0`）像以前一样有一个 IP 地址，但这次，MacVLAN 接口存在于它们自己独特的命名空间中。尽管位于不同的命名空间中，但它们仍然共享相同的父接口，因为这是在将它们移入命名空间之前完成的。

此时，您应该注意到外部主机无法再 ping 通所有 IP 地址。相反，您只能到达`172.16.10.2`的`eth0` IP 地址。原因很简单。正如您所记得的，命名空间类似于**虚拟路由和转发**（**VRF**），并且有自己的路由表。如果您检查一下两个命名空间的路由表，您会发现它们都没有默认路由：

```
user@net1:~$ sudo ip netns exec **namespace1** ip route
172.16.10.0/24 dev macvlan1  proto kernel  scope link  src 172.16.10.5
user@net1:~$ sudo ip netns exec **namespace2** ip route
172.16.10.0/24 dev macvlan2  proto kernel  scope link  src 172.16.10.6
user@net1:~$
```

为了使这些接口在网络外可达，我们需要为每个命名空间指定一个默认路由，指向该子网上的网关（`172.16.10.1`）。同样，这是将 MacVLAN 接口 addressing 在与父接口相同的子网中的好处。路由已经存在于物理网络上。添加路由并重新测试：

```
user@net1:~$ sudo ip netns exec namespace1 ip route \
add 0.0.0.0/0 via 172.16.10.1
user@net1:~$ sudo ip netns exec namespace2 ip route \
add 0.0.0.0/0 via 172.16.10.1
```

从外部测试主机（为简洁起见删除了一些输出）：

```
user@test_server:~$** ping 172.16.10.2 -c 2
PING 172.16.10.2 (172.16.10.2) 56(84) bytes of data.
64 bytes from 172.16.10.2: icmp_seq=1 ttl=63 time=0.459 ms
64 bytes from 172.16.10.2: icmp_seq=2 ttl=63 time=0.441 ms
user@test_server:~$** ping 172.16.10.5 -c 2
PING 172.16.10.5 (172.16.10.5) 56(84) bytes of data.
64 bytes from 172.16.10.5: icmp_seq=1 ttl=63 time=0.521 ms
64 bytes from 172.16.10.5: icmp_seq=2 ttl=63 time=0.528 ms
user@test_server:~$** ping 172.16.10.6 -c 2
PING 172.16.10.6 (172.16.10.6) 56(84) bytes of data.
64 bytes from 172.16.10.6: icmp_seq=1 ttl=63 time=0.524 ms
64 bytes from 172.16.10.6: icmp_seq=2 ttl=63 time=0.551 ms

```

因此，虽然外部连接似乎按预期工作，但请注意，这些接口都无法相互通信：

```
user@net1:~$ sudo ip netns exec **namespace2** ping **172.16.10.5
PING 172.16.10.5 (172.16.10.5) 56(84) bytes of data.
--- 172.16.10.5 ping statistics ---
5 packets transmitted, 0 received, **100% packet loss**, time 0ms
user@net1:~$ sudo ip netns exec **namespace2** ping **172.16.10.2
PING 172.16.10.2 (172.16.10.2) 56(84) bytes of data.
--- 172.16.10.2 ping statistics ---
5 packets transmitted, 0 received, **100% packet loss**, time 0ms
user@net1:~$
```

这似乎很奇怪，因为它们都共享相同的父接口。问题在于 MacVLAN 接口的配置方式。MacVLAN 接口类型支持四种不同的模式：

+   **VEPA**：**虚拟以太网端口聚合器**（**VEPA**）模式强制所有源自 MacVLAN 接口的流量从父接口出去，无论目的地如何。即使流量的目的地是共享同一父接口的另一个 MacVLAN 接口，也会受到此策略的影响。在第 2 层场景中，由于标准生成树规则，两个 MacVLAN 接口之间的通信可能会被阻止。您可以在上游路由器上在两者之间进行路由。

+   **桥接**：MacVLAN 桥接模式模仿标准 Linux 桥接。允许在同一父接口上的两个 MacVLAN 接口之间直接进行通信，而无需经过主机的父接口。这对于您期望在同一父接口上跨接口进行高级别通信的情况非常有用。

+   **私有**：此模式类似于 VEPA 模式，具有完全阻止在同一父接口上的接口之间通信的功能。即使允许流量经过父接口然后回流到主机，通信也会被丢弃。

+   **透传**：旨在直接将父接口与 MacVLAN 接口绑定。在此模式下，每个父接口只允许一个 MacVLAN 接口，并且 MacVLAN 接口继承父接口的 MAC 地址。

如果不知道在哪里查找，很难分辨出来，我们的 MacVLAN 接口碰巧是 VEPA 类型，这恰好是默认值。我们可以通过向`ip`命令传递详细信息（`-d`）标志来查看这一点：

```
user@net1:~$ sudo ip netns exec namespace1 ip -d link show
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0
20: **macvlan1@if2**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/ether 36:90:37:f6:08:cc brd ff:ff:ff:ff:ff:ff promiscuity 0
 macvlan  mode vepa
user@net1:~$
```

在我们的情况下，VEPA 模式阻止了两个命名空间接口直接通信。更常见的是，MacVLAN 接口被定义为类型`bridge`，以允许在同一父接口上的接口之间进行通信。然而，即使在这种模式下，子接口也不被允许直接与直接分配给父接口的 IP 地址（在本例中为`172.16.10.2`）进行通信。这应该是一个单独的段落。

```
user@net1:~$ sudo ip netns del namespace1
user@net1:~$ sudo ip netns del namespace2
```

现在我们可以重新创建两个接口，为每个 MacVLAN 接口指定`bridge`模式：

```
user@net1:~$ sudo ip netns add namespace1
user@net1:~$ sudo ip link add macvlan1 link eth0 type \
macvlan **mode bridge
user@net1:~$ sudo ip link set macvlan1 netns namespace1
user@net1:~$ sudo ip netns exec namespace1 ip address \
add 172.16.10.5/24 dev macvlan1
user@net1:~$ sudo ip netns exec namespace1 ip link set \
dev macvlan1 up

user@net1:~$ sudo ip netns add namespace2
user@net1:~$ sudo ip link add macvlan2 link eth0 type \
macvlan **mode bridge
user@net1:~$ sudo ip link set macvlan2 netns namespace2
user@net1:~$ sudo ip netns exec namespace2 sudo ip address \
add 172.16.10.6/24 dev macvlan2
user@net1:~$ sudo ip netns exec namespace2 ip link set \
dev macvlan2 up
```

在指定了`bridge`模式之后，我们可以验证这两个接口可以直接互连：

```
user@net1:~$ sudo ip netns exec **namespace1 ping 172.16.10.6 -c 2
PING 172.16.10.6 (172.16.10.6) 56(84) bytes of data.
64 bytes from 172.16.10.6: icmp_seq=1 ttl=64 time=0.041 ms
64 bytes from 172.16.10.6: icmp_seq=2 ttl=64 time=0.030 ms
--- 172.16.10.6 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.030/0.035/0.041/0.008 ms
user@net1:~$
```

然而，我们也注意到我们仍然无法到达在父接口（`eth0`）上定义的主机 IP 地址：

```
user@net1:~$ sudo ip netns exec **namespace1 ping 172.16.10.2 -c 2
PING 172.16.10.2 (172.16.10.2) 56(84) bytes of data.
--- 172.16.10.2 ping statistics ---
2 packets transmitted, 0 received, **100% packet loss**, time 1008ms
user@net1:~$
```

# 使用 Docker MacVLAN 网络驱动程序

当我开始写这本书时，Docker 的当前版本是 1.10，那时 MacVLAN 功能已经包含在 Docker 的候选版本中。自那时起，1.12 版本已经发布，将 MacVLAN 推入软件的发布版本。也就是说，使用 MacVLAN 驱动程序的唯一要求是确保您安装了 1.12 或更新版本的 Docker。在本章中，我们将讨论如何为从 Docker 创建的容器使用 MacVLAN 网络驱动程序。

## 准备工作

在本教程中，我们将使用两台运行 Docker 的 Linux 主机。我们的实验拓扑将包括两个生活在同一网络上的 Docker 主机。它将如下所示：

![准备工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_05.jpg)

假设每个主机都运行着 1.12 或更高版本的 Docker，以便可以访问 MacVLAN 驱动程序。主机应该有一个单独的 IP 接口，并且 Docker 应该处于默认配置状态。在某些情况下，我们所做的更改可能需要您具有系统的根级访问权限。

## 如何做…

就像所有其他用户定义的网络类型一样，MacVLAN 驱动程序是通过`docker network`子命令处理的。创建 MacVLAN 类型网络与创建任何其他网络类型一样简单，但有一些特定于此驱动程序的事项需要牢记。

+   在定义网络时，您需要指定上游网关。请记住，MacVLAN 接口显示在父接口的相同接口上。它们需要主机或接口的上游网关才能访问外部子网。

+   在其他用户定义的网络类型中，如果您决定不指定一个子网，Docker 会为您生成一个子网供您使用。虽然 MacVLAN 驱动程序仍然是这种情况，但除非您指定父接口所在的网络，否则它将无法正常工作。就像我们在上一个教程中看到的那样，MacVLAN 依赖于上游网络设备知道如何路由 MacVLAN 接口。这是通过在与父接口相同的子网上定义容器的 MacVLAN 接口来实现的。您还可以选择使用没有定义 IP 地址的父接口。在这些情况下，只需确保您在 Docker 中定义网络时指定的网关可以通过父接口到达。

+   作为驱动程序的选项，您需要指定希望用作所有连接到 MacVLAN 接口的容器的父接口的接口。如果不将父接口指定为选项，Docker 将创建一个虚拟网络接口并将其用作父接口。这将阻止该网络与外部网络的任何通信。

+   使用 MacVLAN 驱动程序创建网络时，可以使用`--internal 标志`。当指定时，父接口被定义为虚拟接口，阻止流量离开主机。

+   MacVLAN 用户定义网络与父接口之间是一对一的关系。也就是说，您只能在给定的父接口上定义一个 MacVLAN 类型网络。

+   一些交换机供应商限制每个端口可以学习的 MAC 地址数量。虽然这个数字通常非常高，但在使用这种网络类型时，请确保考虑到这一点。

+   与其他用户定义的网络类型一样，您可以指定 IP 范围或一组辅助地址，希望 Docker 的 IPAM 不要分配给容器。在 MacVLAN 模式下，这些设置更为重要，因为您直接将容器呈现到物理网络上。

考虑到我们当前的实验室拓扑，我们可以在每个主机上定义网络如下：

```
user@docker1:~$ docker network create -d macvlan \
--subnet 10.10.10.0/24 --ip-range 10.10.10.0/25 \
--gateway=10.10.10.1 --aux-address docker1=10.10.10.101 \
--aux-address docker2=10.10.10.102 -o parent=eth0 macvlan_net

user@docker2:~$ docker network create -d macvlan \
--subnet 10.10.10.0/24 --ip-range 10.10.10.128/25 \
--gateway=10.10.10.1 --aux-address docker1=10.10.10.101 \
--aux-address docker2=10.10.10.102 -o parent=eth0 macvlan_net
```

使用这种配置，网络上的每个主机将使用可用子网的一半，本例中为`/25`。由于 Docker 的 IPAM 自动为我们保留网关 IP 地址，因此无需通过将其定义为辅助地址来阻止其分配。但是，由于 Docker 主机接口本身确实位于此范围内，我们确实需要使用辅助地址来保留这些地址。

现在，我们可以在每个主机上定义容器，并验证它们是否可以彼此通信：

```
user@docker1:~$ docker run -d --name=web1 \
--net=macvlan_net jonlangemak/web_server_1
user@docker1:~$ **docker exec web1 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
7: **eth0@if2**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
    link/ether 02:42:0a:0a:0a:02 brd ff:ff:ff:ff:ff:ff
    inet **10.10.10.2/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:aff:fe0a:a02/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
user@docker2:~$ docker run -d --name=web2 \
--net=macvlan_net jonlangemak/web_server_2
user@docker2:~$ **docker exec web2 ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
4: **eth0@if2**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
    link/ether 02:42:0a:0a:0a:80 brd ff:ff:ff:ff:ff:ff
    inet **10.10.10.128/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:aff:fe0a:a80/64 scope link
       valid_lft forever preferred_lft forever
user@docker2:~$
```

请注意，在容器运行时不需要发布端口。由于容器此时具有唯一可路由的 IP 地址，因此不需要进行端口发布。任何容器都可以在其自己的唯一 IP 地址上提供任何服务。

与其他网络类型一样，Docker 为每个容器创建一个网络命名空间，然后将容器的 MacVLAN 接口映射到其中。此时，我们的拓扑如下所示：

![操作步骤如下...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_06.jpg)

### 注意

可以通过检查容器本身或链接 Docker 的`netns`目录来找到命名空间名称，就像我们在前面的章节中看到的那样，因此`ip netns`子命令可以查询 Docker 定义的网络命名空间。

从一个生活在子网之外的外部测试主机，我们可以验证每个容器服务都可以通过容器的 IP 地址访问到：

```
user@test_server:~$ **curl http://10.10.10.2
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #1 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@test_server:~$ **curl http://10.10.10.128
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #2 - Running on port 80**</span>
    </h1>
</body>
  </html>
[root@tools ~]#
```

但是，您会注意到连接到 MacVLAN 网络的容器尽管位于同一接口上，但无法从本地主机访问：

```
user@docker1:~$ **ping 10.10.10.2
PING 10.10.10.2 (10.10.10.2) 56(84) bytes of data.
From 10.10.10.101 icmp_seq=1 **Destination Host Unreachable
--- 10.10.10.2 ping statistics ---
5 packets transmitted, 0 received, +1 errors, **100% packet loss**, time 0ms
user@docker1:~$
```

Docker 当前的实现仅支持 MacVLAN 桥接模式。我们可以通过检查容器内接口的详细信息来验证 MacVLAN 接口的操作模式：

```
user@docker1:~$ docker exec web1 ip -d link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
5: **eth0@if2**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
    link/ether 02:42:0a:0a:0a:02 brd ff:ff:ff:ff:ff:ff
 macvlan  mode bridge
user@docker1:~$
```

# 理解 IPVLAN 接口

IPVLAN 是 MacVLAN 的一种替代方案。IPVLAN 有两种模式。第一种是 L2 模式，它的操作方式与 MacVLAN 非常相似，唯一的区别在于 MAC 地址的分配方式。在 IPVLAN 模式下，所有逻辑 IP 接口使用相同的 MAC 地址。这使得您可以保持父 NIC 不处于混杂模式，并且还可以防止您遇到任何可能的 NIC 或交换机端口 MAC 限制。第二种模式是 IPVLAN 层 3。在层 3 模式下，IPVLAN 就像一个路由器，转发 IPVLAN 连接网络中的单播数据包。在本文中，我们将介绍基本的 IPVLAN 网络结构，以了解它的工作原理和实现方式。

## 准备工作

在本文中，我们将使用本章中“理解 MacVLAN 接口”食谱中的相同 Linux 主机（`net1`和`net2`）。有关拓扑结构的更多信息，请参阅本章中“理解 MacVLAN”食谱的“准备工作”部分。

### 注意

较旧版本的`iproute2`工具集不包括对 IPVLAN 的完全支持。如果 IPVLAN 配置的命令不起作用，很可能是因为您使用的是不支持的较旧版本。您可能需要更新以获取具有完全支持的新版本。较旧的版本对 IPVLAN 有一些支持，但缺乏定义模式（L2 或 L3）的能力。

## 操作步骤

如前所述，IPVLAN 的 L2 模式在功能上几乎与 MacVLAN 相同。主要区别在于 IPVLAN 利用相同的 MAC 地址连接到同一主机的所有 IPVLAN 接口。您会记得，MacVLAN 接口利用不同的 MAC 地址连接到同一父接口的每个 MacVLAN 接口。

我们可以创建与 MacVLAN 配方中相同的接口，以显示接口地址是使用相同的 MAC 地址创建的：

```
user@net1:~$ sudo ip link add ipvlan1 link eth0  **type ipvlan mode l2
user@net1:~$ sudo ip address add 172.16.10.5/24 dev ipvlan1
user@net1:~$ sudo ip link set dev ipvlan1 up

user@net1:~$ sudo ip link add ipvlan2 link eth0 **type ipvlan mode l2
user@net1:~$ sudo ip address add 172.16.10.6/24 dev ipvlan2
user@net1:~$ sudo ip link set dev ipvlan2 up
```

请注意，配置中唯一的区别是我们将类型指定为 IPVLAN，模式指定为 L2。在 IPVLAN 的情况下，默认模式是 L3，因此我们需要指定 L2 以使接口以这种方式运行。由于 IPVLAN 接口继承了父接口的 MAC 地址，我们的拓扑应该是这样的：

![操作方法...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_07.jpg)

我们可以通过检查接口本身来证明这一点：

```
user@net1:~$ ip -d link
…<loopback interface removed for brevity>…
2: **eth0**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether **00:0c:29:2d:dd:79** brd ff:ff:ff:ff:ff:ff promiscuity 1 addrgenmode eui64
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:2d:dd:83 brd ff:ff:ff:ff:ff:ff promiscuity 0 addrgenmode eui64
28: **ipvlan1@eth0**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/ether **00:0c:29:2d:dd:79** brd ff:ff:ff:ff:ff:ff promiscuity 0
 ipvlan  mode l2** addrgenmode eui64
29: **ipvlan2@eth0**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/ether **00:0c:29:2d:dd:79** brd ff:ff:ff:ff:ff:ff promiscuity 0
 ipvlan  mode l2** addrgenmode eui64
user@net1:~$
```

如果我们从本地子网外部向这些 IP 发起流量，我们可以通过检查上游网关的 ARP 表来验证每个 IP 报告相同的 MAC 地址：

```
switch#show ip arp vlan 10
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  172.16.10.6             0   000c.292d.dd79  ARPA   Vlan30
Internet  172.16.10.5             0   000c.292d.dd79  ARPA   Vlan30
Internet  172.16.10.2           111   000c.292d.dd79  ARPA   Vlan30
Internet  172.16.10.3           110   000c.2959.caca  ARPA   Vlan30
Internet  172.16.10.1             -   0021.d7c5.f245  ARPA   Vlan30
```

虽然我们在这里不会展示一个例子，但是 IPVLAN 接口在 L2 模式下也像我们在最近几个配方中看到的 MacVLAN 接口类型一样具有命名空间感知能力。唯一的区别在于接口 MAC 地址，就像我们在前面的代码中看到的那样。与父接口无法与子接口通信以及反之的相同限制也适用。

现在我们知道了 IPVLAN 在 L2 模式下的工作原理，让我们讨论一下 IPVLAN L3 模式。L3 模式与我们到目前为止所见到的情况有很大不同。正如 L3 模式的名称所暗示的那样，这种接口类型在所有附加的子接口之间路由流量。这在命名空间配置中最容易理解。例如，让我们看一下这个快速实验的拓扑：

![操作方法...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_08.jpg)

在上图中，您可以看到我在我们的两个实验主机上创建了四个独立的命名空间。我还创建了四个独立的 IPVLAN 接口，将它们映射到不同的命名空间，并为它们分配了各自独特的 IP 地址。由于这些是 IPVLAN 接口，您会注意到所有 IPVLAN 接口共享父接口的 MAC 地址。为了构建这个拓扑，我在每个相应的主机上使用了以下配置：

```
user@net1:~$ sudo ip link del dev ipvlan1
user@net1:~$ sudo ip link del dev ipvlan2
user@net1:~$ sudo ip netns add namespace1
user@net1:~$ sudo ip netns add namespace2
user@net1:~$ sudo ip link add ipvlan1 link eth0 type ipvlan mode l3
user@net1:~$ sudo ip link add ipvlan2 link eth0 type ipvlan mode l3
user@net1:~$ sudo ip link set ipvlan1 netns namespace1
user@net1:~$ sudo ip link set ipvlan2 netns namespace2
user@net1:~$ sudo ip netns exec namespace1 ip address \
add 10.10.20.10/24 dev ipvlan1
user@net1:~$ sudo ip netns exec namespace1 ip link set dev ipvlan1 up
user@net1:~$ sudo ip netns exec namespace2 sudo ip address \
add 10.10.30.10/24 dev ipvlan2
user@net1:~$ sudo ip netns exec namespace2 ip link set dev ipvlan2 up

user@net2:~$ sudo ip netns add namespace3
user@net2:~$ sudo ip netns add namespace4
user@net2:~$ sudo ip link add ipvlan3 link eth0 type ipvlan mode l3
user@net2:~$ sudo ip link add ipvlan4 link eth0 type ipvlan mode l3
user@net2:~$ sudo ip link set ipvlan3 netns namespace3
user@net2:~$ sudo ip link set ipvlan4 netns namespace4
user@net2:~$ sudo ip netns exec namespace3 ip address \
add 10.10.40.10/24 dev ipvlan3
user@net2:~$ sudo ip netns exec namespace3 ip link set dev ipvlan3 up
user@net2:~$ sudo ip netns exec namespace4 sudo ip address \
add 10.10.40.11/24 dev ipvlan4
user@net2:~$ sudo ip netns exec namespace4 ip link set dev ipvlan4 up
```

一旦配置完成，您会注意到唯一可以相互通信的接口是主机`net2`上的那些接口（`10.10.40.10`和`10.10.40.11`）。让我们逻辑地看一下这个拓扑，以理解其中的原因：

![操作方法...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_09.jpg)

从逻辑上看，它开始看起来像一个路由网络。你会注意到所有分配的 IP 地址都是唯一的，没有重叠。正如我之前提到的，IPVLAN L3 模式就像一个路由器。从概念上看，你可以把父接口看作是那个路由器。如果我们从三层的角度来看，只有命名空间 3 和 4 中的接口可以通信，因为它们在同一个广播域中。其他命名空间需要通过网关进行路由才能相互通信。让我们检查一下所有命名空间的路由表，看看情况如何：

```
user@net1:~$ sudo ip netns exec **namespace1** ip route
10.10.20.0/24** dev ipvlan1  proto kernel  scope link  src 10.10.20.10
user@net1:~$ sudo ip netns exec **namespace2** ip route
10.10.30.0/24** dev ipvlan2  proto kernel  scope link  src 10.10.30.10
user@net2:~$ sudo ip netns exec **namespace3** ip route
10.10.40.0/24** dev ipvlan3  proto kernel  scope link  src 10.10.40.10
user@net2:~$ sudo ip netns exec **namespace4** ip route
10.10.40.0/24** dev ipvlan4  proto kernel  scope link  src 10.10.40.11
```

如预期的那样，每个命名空间只知道本地网络。因此，为了让这些接口进行通信，它们至少需要一个默认路由。这就是事情变得有点有趣的地方。IPVLAN 接口不允许广播或组播流量。这意味着如果我们将接口的网关定义为上游交换机，它永远也无法到达，因为它无法进行 ARP。然而，由于父接口就像一种路由器，我们可以让命名空间使用 IPVLAN 接口本身作为网关。我们可以通过以下方式添加默认路由来实现这一点：

```
user@net1:~$ sudo ip netns exec namespace1 ip route add \
default dev ipvlan1
user@net1:~$ sudo ip netns exec namespace2 ip route add \
default dev ipvlan2
user@net2:~$ sudo ip netns exec namespace3 ip route add \
default dev ipvlan3
user@net2:~$ sudo ip netns exec namespace4 ip route add \
default dev ipvlan4
```

在添加这些路由之后，你还需要在每台 Linux 主机上添加路由，告诉它们如何到达这些远程子网。由于这个示例中的两台主机是二层相邻的，最好在主机本身进行这些操作。虽然你也可以依赖默认路由，并在上游网络设备上配置这些路由，但这并不理想。你实际上会在网关上的同一个 L3 接口上进行路由，这不是一个很好的网络设计实践。如果主机不是二层相邻的，那么在多层交换机上添加路由就是必需的。

```
user@net1:~$ sudo ip route add 10.10.40.0/24 via 172.16.10.3
user@net2:~$ sudo ip route add 10.10.20.0/24 via 172.16.10.2
user@net2:~$ sudo ip route add 10.10.30.0/24 via 172.16.10.2
```

在安装了所有路由之后，你应该能够从任何一个命名空间到达所有其他命名空间。

```
user@net1:~$ **sudo ip netns exec namespace1 ping 10.10.30.10 -c 2
PING 10.10.30.10 (10.10.30.10) 56(84) bytes of data.
64 bytes from 10.10.30.10: icmp_seq=1 ttl=64 time=0.047 ms
64 bytes from 10.10.30.10: icmp_seq=2 ttl=64 time=0.033 ms
--- 10.10.30.10 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.033/0.040/0.047/0.007 ms
user@net1:~$ **sudo ip netns exec namespace1 ping 10.10.40.10 -c 2
PING 10.10.40.10 (10.10.40.10) 56(84) bytes of data.
64 bytes from 10.10.40.10: icmp_seq=1 ttl=64 time=0.258 ms
64 bytes from 10.10.40.10: icmp_seq=2 ttl=64 time=0.366 ms
--- 10.10.40.10 ping statistics ---
2 packets transmitted, 2 received, +3 duplicates, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.258/0.307/0.366/0.042 ms
user@net1:~$ **sudo ip netns exec namespace1 ping 10.10.40.11 -c 2
PING 10.10.40.11 (10.10.40.11) 56(84) bytes of data.
64 bytes from 10.10.40.11: icmp_seq=1 ttl=64 time=0.246 ms
64 bytes from 10.10.40.11: icmp_seq=2 ttl=64 time=0.366 ms
--- 10.10.40.11 ping statistics ---
2 packets transmitted, 2 received, +3 duplicates, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.246/0.293/0.366/0.046 ms
user@net1:~$ s
```

正如你所看到的，IPVLAN L3 模式与我们到目前为止所见到的不同。与 MacVLAN 或 IPVLAN L2 不同，你需要告诉网络如何到达这些新接口。

# 使用 Docker IPVLAN 网络驱动程序

正如我们在前一个配方中所看到的，IPVLAN 提供了一些有趣的操作模式，这些模式可能与大规模容器部署相关。目前，Docker 在其实验软件通道中支持 IPVLAN。在本配方中，我们将审查如何使用 Docker IPVLAN 驱动程序消耗附加 IPVLAN 的容器。

## 准备工作

在本配方中，我们将使用两台运行 Docker 的 Linux 主机。我们的实验拓扑将如下所示：

![准备工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_10.jpg)

假设每个主机都在运行 Docker 的实验通道，以便访问实验性的 IPVLAN 网络驱动程序。请参阅有关使用和消费实验软件通道的第 1 个配方。主机应该有一个单独的 IP 接口，并且 Docker 应该处于默认配置。在某些情况下，我们所做的更改可能需要您具有系统的根级访问权限。

## 如何操作…

一旦您的主机运行了实验性代码，请通过查看`docker info`的输出来验证您是否处于正确的版本：

```
user@docker1:~$ docker info
…<Additional output removed for brevity>…
Server Version: 1.12.2
…<Additional output removed for brevity>…
Experimental: true
user@docker1:~$
```

在撰写本文时，您需要在 Docker 的实验版本上才能使用 IPVLAN 驱动程序。

Docker IPVLAN 网络驱动程序提供了层 2 和层 3 操作模式。由于 IPVLAN L2 模式与我们之前审查的 MacVLAN 配置非常相似，因此我们将专注于在本配方中实现 L3 模式。我们需要做的第一件事是定义网络。在这样做之前，在使用 IPVLAN 网络驱动程序时需要记住一些事情：

+   虽然它允许您在定义网络时指定网关，但该设置将被忽略。请回想一下前一个配方，您需要使用 IPVLAN 接口本身作为网关，而不是上游网络设备。Docker 会为您配置这个。

+   作为驱动程序的一个选项，您需要指定要用作所有附加 IPVLAN 接口的父接口的接口。如果您不将父接口指定为选项，Docker 将创建一个虚拟网络接口，并将其用作父接口。这将阻止该网络与外部网络进行通信。

+   在使用 IPVLAN 驱动程序创建网络时，可以使用`--internal`标志。当指定时，父接口被定义为虚拟接口，阻止流量离开主机。

+   如果您没有指定子网，Docker IPAM 将为您选择一个。这是不建议的，因为这些是可路由的子网。不同 Docker 主机上的 IPAM 可能会选择相同的子网。请始终指定您希望定义的子网。

+   IPVLAN 用户定义网络和父接口之间是一对一的关系。也就是说，在给定的父接口上只能定义一个 IPVLAN 类型的网络。

您会注意到，许多前面的观点与适用于 Docker MacVLAN 驱动程序的观点相似。一个重要的区别在于，我们不希望使用与父接口相同的网络。在我们的示例中，我们将在主机`docker1`上使用子网`10.10.20.0/24`，在主机`docker3`上使用子网`10.10.30.0/24`。现在让我们在每台主机上定义网络：

```
user@docker1:~$ docker network  create -d ipvlan -o parent=eth0 \
--subnet=10.10.20.0/24 -o ipvlan_mode=l3 ipvlan_net
16a6ed2b8d2bdffad04be17e53e498cc48b71ca0bdaed03a565542ba1214bc37

user@docker3:~$ docker network  create -d ipvlan -o parent=eth0 \
--subnet=10.10.30.0/24 -o ipvlan_mode=l3 ipvlan_net
6ad00282883a83d1f715b0f725ae9115cbd11034ec59347524bebb4b673ac8a2
```

创建后，我们可以在每个使用 IPVLAN 网络的主机上启动一个容器：

```
user@docker1:~$ docker run -d --name=web1 --net=ipvlan_net \
jonlangemak/web_server_1
93b6be9e83ee2b1eaef26abd2fb4c653a87a75cea4b9cd6bf26376057d77f00f

user@docker3:~$ docker run -d --name=web2 --net=ipvlan_net \
jonlangemak/web_server_2
89b8b453849d12346b9694bb50e8376f30c2befe4db8836a0fd6e3950f57595c
```

您会注意到，我们再次不需要处理发布端口。容器被分配了一个完全可路由的 IP 地址，并且可以在该 IP 上提供任何服务。分配给容器的 IP 地址将来自指定的子网。在这种情况下，我们的拓扑结构如下：

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_11.jpg)

一旦运行起来，您会注意到容器没有任何连接。这是因为网络不知道如何到达每个 IPVLAN 网络。为了使其工作，我们需要告诉上游网络设备如何到达每个子网。为此，我们将在多层交换机上添加以下路由：

```
ip route 10.10.20.0 255.255.255.0 10.10.10.101
ip route 10.10.30.0 255.255.255.0 192.168.50.101
```

一旦建立了这种路由，我们就能够路由到远程容器并访问它们提供的任何服务：

```
user@docker1:~$ **docker exec web1 curl -s http://10.10.30.2
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #2 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

您会注意到，在这种模式下，容器还可以访问主机接口：

```
user@docker1:~$ **docker exec -it web1 ping 10.10.10.101 -c 2
PING 10.10.10.101 (10.10.10.101): 48 data bytes
56 bytes from 10.10.10.101: icmp_seq=0 ttl=63 time=0.232 ms
56 bytes from 10.10.10.101: icmp_seq=1 ttl=63 time=0.321 ms
--- 10.10.10.101 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.232/0.277/0.321/0.045 ms
user@docker1:~$
```

虽然这样可以工作，但重要的是要知道这是通过遍历父接口到多层交换机然后再返回来实现的。如果我们尝试在相反的方向进行 ping，上游交换机（网关）会生成 ICMP 重定向。

```
user@docker1:~$ ping 10.10.20.2 -c 2
PING 10.10.20.2 (10.10.20.2) 56(84) bytes of data.
From **10.10.10.1**: icmp_seq=1 **Redirect Host(New nexthop: 10.10.10.101)
64 bytes from 10.10.20.2: icmp_seq=1 ttl=64 time=0.270 ms
From **10.10.10.1**: icmp_seq=2 **Redirect Host(New nexthop: 10.10.10.101)
64 bytes from 10.10.20.2: icmp_seq=2 ttl=64 time=0.368 ms
--- 10.10.20.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1000ms
rtt min/avg/max/mdev = 0.270/0.319/0.368/0.049 ms
user@docker1:~$
```

因此，虽然主机到容器的连接是有效的，但如果您需要主机与本地容器通信，则这不是最佳模型。

# 使用 MacVLAN 和 IPVLAN 网络标记 VLAN ID

MacVLAN 和 IPVLAN Docker 网络类型都具有的一个特性是能够在特定 VLAN 上标记容器。这是可能的，因为这两种网络类型都利用了一个父接口。在这个教程中，我们将向您展示如何创建支持 VLAN 标记或 VLAN 感知的 Docker 网络类型。由于这个功能在任一网络类型的情况下都是相同的，我们将重点介绍如何在 MacVLAN 类型网络中配置这个功能。

## 准备工作

在这个教程中，我们将使用单个 Docker 主机来演示 Linux 主机如何向上游网络设备发送 VLAN 标记帧。我们的实验拓扑将如下所示：

![准备工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_12.jpg)

假设这个主机正在运行 1.12 版本。主机有两个网络接口，`eth0`的 IP 地址是`10.10.10.101`，`eth1`是启用的，但没有配置 IP 地址。

## 操作步骤…

MacVLAN 和 IPVLAN 网络驱动程序带来的一个有趣特性是能够提供子接口。子接口是通常物理接口的逻辑分区。对物理接口进行分区的标准方法是利用 VLAN。你通常会听到这被称为 dot1q 干线或 VLAN 标记。为了做到这一点，上游网络接口必须准备好接收标记帧并能够解释标记。在我们之前的所有示例中，上游网络端口都是硬编码到特定的 VLAN。这就是这台服务器的`eth0`接口的情况。它插入了交换机上的一个端口，该端口静态配置为 VLAN 10。此外，交换机还在 VLAN 10 上有一个 IP 接口，我们的情况下是`10.10.10.1/24`。它充当服务器的默认网关。从服务器的`eth0`接口发送的帧被交换机接收并最终进入 VLAN 10。这一点非常简单明了。

另一个选择是让服务器告诉交换机它希望在哪个 VLAN 中。为此，我们在服务器上创建一个特定于给定 VLAN 的子接口。离开该接口的流量将被标记为 VLAN 号并发送到交换机。为了使其工作，交换机端口需要配置为**干线**。干线是可以携带多个 VLAN 并且支持 VLAN 标记（dot1q）的接口。当交换机接收到帧时，它会引用帧中的 VLAN 标记，并根据标记将流量放入正确的 VLAN 中。从逻辑上讲，您可以将干线配置描述如下：

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_13.jpg)

我们将`eth1`接口描述为一个宽通道，可以支持连接到大量 VLAN。我们可以看到干线端口可以连接到所有可能的 VLAN 接口，这取决于它接收到的标记。`eth0`接口静态绑定到 VLAN 10 接口。

### 注意

在生产环境中，限制干线端口上允许的 VLAN 是明智的。不这样做意味着某人可能只需指定正确的 dot1q 标记就可以潜在地访问交换机上的任何 VLAN。

这个功能已经存在很长时间了，Linux 系统管理员可能熟悉用于创建 VLAN 标记子接口的手动过程。有趣的是，Docker 现在可以为您管理这一切。例如，我们可以创建两个不同的 MacVLAN 网络：

```
user@docker1:~$ docker network create -d macvlan **-o parent=eth1.19 \
 --subnet=10.10.90.0/24 --gateway=10.10.90.1 vlan19
8f545359f4ca19ee7349f301e5af2c84d959e936a5b54526b8692d0842a94378

user@docker1:~$ docker network create -d macvlan **-o parent=eth1.20 \
--subnet=192.168.20.0/24 --gateway=192.168.20.1 vlan20
df45e517a6f499d589cfedabe7d4a4ef5a80ed9c88693f255f8ceb91fe0bbb0f
user@docker1:~$
```

接口的定义与任何其他 MacVLAN 接口一样。不同的是，我们在父接口名称上指定了`.19`和`.20`。在接口名称后面指定带有数字的点是定义子接口的常见语法。如果我们查看主机网络接口，我们应该会看到两个新接口的添加：

```
user@docker1:~$ ip -d link show
…<Additional output removed for brevity>…
5: **eth1.19@eth1**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default
    link/ether 00:0c:29:50:b8:d6 brd ff:ff:ff:ff:ff:ff promiscuity 0
 vlan protocol 802.1Q id 19** <REORDER_HDR> addrgenmode eui64
6: **eth1.20@eth1**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default
    link/ether 00:0c:29:50:b8:d6 brd ff:ff:ff:ff:ff:ff promiscuity 0
 vlan protocol 802.1Q id 20** <REORDER_HDR> addrgenmode eui64
user@docker1:~$
```

从这个输出中我们可以看出，这些都是 MacVLAN 或 IPVLAN 接口，其父接口恰好是物理接口`eth1`。

如果我们在这两个网络上启动容器，我们会发现它们最终会进入基于我们指定的网络的 VLAN 19 或 VLAN 20 中：

```
user@docker1:~$ **docker run --net=vlan19 --name=web1 -d \
jonlangemak/web_server_1
7f54eec28098eb6e589c8d9601784671b9988b767ebec5791540e1a476ea5345
user@docker1:~$
user@docker1:~$ **docker run --net=vlan20 --name=web2 -d \
jonlangemak/web_server_2
a895165c46343873fa11bebc355a7826ef02d2f24809727fb4038a14dd5e7d4a
user@docker1:~$
user@docker1:~$ **docker exec web1 ip addr show dev eth0
7: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
    link/ether 02:42:0a:0a:5a:02 brd ff:ff:ff:ff:ff:ff
    inet **10.10.90.2/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:aff:fe0a:5a02/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
user@docker1:~$ **docker exec web2 ip addr show dev eth0
8: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
    link/ether 02:42:c0:a8:14:02 brd ff:ff:ff:ff:ff:ff
    inet **192.168.20.2/24** scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:c0ff:fea8:1402/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

如果我们尝试向它们的网关发送流量，我们会发现两者都是可达的：

```
user@docker1:~$ **docker exec -it web1 ping 10.10.90.1 -c 2
PING 10.10.90.1 (10.10.90.1): 48 data bytes
56 bytes from 10.10.90.1: icmp_seq=0 ttl=255 time=0.654 ms
56 bytes from 10.10.90.1: icmp_seq=1 ttl=255 time=0.847 ms
--- 10.10.90.1 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.654/0.750/0.847/0.097 ms
user@docker1:~$ **docker exec -it web2 ping 192.168.20.1 -c 2
PING 192.168.20.1 (192.168.20.1): 48 data bytes
56 bytes from 192.168.20.1: icmp_seq=0 ttl=255 time=0.703 ms
56 bytes from 192.168.20.1: icmp_seq=1 ttl=255 time=0.814 ms
--- 192.168.20.1 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.703/0.758/0.814/0.056 ms
user@docker1:~$
```

如果我们捕获服务器发送的帧，甚至能够在第 2 层标头中看到 dot1q（VLAN）标记：

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_09_14.jpg)

与 Docker 创建的其他网络结构一样，Docker 也会在您删除这些用户定义的网络时进行清理。此外，如果您更喜欢自己建立子接口，Docker 可以使用您已经创建的接口，只要名称与您指定的父接口相同即可。

能够在用户定义的网络中指定 VLAN 标签是一件大事，这使得将容器呈现给物理网络变得更加容易。


# 第十章：利用 IPv6

在本章中，我们将涵盖以下教程：

+   IPv6 命令行基础知识

+   在 Docker 中启用 IPv6 功能

+   使用 IPv6 启用的容器

+   配置 NDP 代理

+   用户定义的网络和 IPv6

# 介绍

在本书的这一部分，我们一直专注于 IPv4 网络。然而，IPv4 并不是我们唯一可用的 IP 协议。尽管 IPv4 仍然是最广为人知的协议，但 IPv6 开始引起了重大关注。公共 IPv4 空间已经耗尽，许多人开始预见到私有 IPv4 分配用尽的问题。IPv6 看起来可以通过定义更大的可用 IP 空间来解决这个问题。然而，IPv6 与 IPv4 有一些不同之处，使一些人认为实施 IPv6 将会很麻烦。我认为，当你考虑部署容器技术时，你也应该考虑如何有效地利用 IPv6。尽管 IPv6 是一个不同的协议，但它很快将成为许多网络的要求。随着容器代表着在你的网络上引入更多 IP 端点的可能性，尽早进行过渡是一个好主意。在本章中，我们将看看 Docker 目前支持的 IPv6 功能。

# IPv6 命令行基础知识

即使你了解 IPv6 协议的基础知识，第一次在 Linux 主机上使用 IPv6 可能会有点令人畏惧。与 IPv4 类似，IPv6 有其独特的一套命令行工具，可以用来配置和排除 IPv6 连接问题。其中一些工具与我们在 IPv4 中使用的相同，只是语法略有不同。其他工具则是完全独特于 IPv6。在这个教程中，我们将介绍如何配置和验证基本的 IPv6 连接。

## 准备工作

在这个教程中，我们将使用由两个 Linux 主机组成的小型实验室：

![准备工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_10_01.jpg)

每台主机都分配了一个 IPv4 地址和一个 IPv6 地址给其物理接口。你需要 root 级别的访问权限来对每台主机进行网络配置更改。

### 注意

这个教程的目的不是教授 IPv6 或 IPv6 网络设计的基础知识。本教程中的示例仅供举例。虽然在示例中我们可能会涵盖一些基础知识，但假定读者已经对 IPv6 协议的工作原理有基本的了解。

## 如何做…

如前图所示，每台 Linux 主机都被分配了 IPv4 和 IPv6 IP 地址。这些都是作为主机网络配置脚本的一部分进行配置的。以下是两台实验主机的示例配置：

+   `net1.lab.lab`

```
auto eth0
iface eth0 inet static
        address 172.16.10.2
        netmask 255.255.255.0
        gateway 172.16.10.1
        dns-nameservers 10.20.30.13
        dns-search lab.lab
iface eth0 inet6 static
 address 2003:ab11::1
 netmask 64

```

+   `net2.lab.lab`

```
auto eth0
iface eth0 inet static
        address 172.16.10.3
        netmask 255.255.255.0
        gateway 172.16.10.1
        dns-nameservers 10.20.30.13
        dns-search lab.lab
iface eth0 inet6 static
 address 2003:ab11::2
 netmask 64

```

请注意，在每种情况下，我们都将 IPv6 地址添加到现有的物理网络接口上。在这种类型的配置中，IPv4 和 IPv6 地址共存于同一个网卡上。这通常被称为运行**双栈**，因为两种协议共享同一个物理适配器。配置完成后，您需要重新加载接口以使配置生效。然后，您应该能够通过使用`ifconfig`工具或`ip`（`iproute2`）工具集来确认每台主机是否具有正确的配置：

```
user@net1:~$ **ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 00:0c:29:2d:dd:79
inet addr:172.16.10.2  Bcast:172.16.10.255  Mask:255.255.255.0
 inet6 addr: fe80::20c:29ff:fe2d:dd79/64 Scope:Link
 inet6 addr: 2003:ab11::1/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:308 errors:0 dropped:0 overruns:0 frame:0
          TX packets:348 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:32151 (32.1 KB)  TX bytes:36732 (36.7 KB)
user@net1:~$

user@net2:~$ ip -6 addr show dev eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qlen 1000
 inet6 2003:ab11::2/64 scope global
       valid_lft forever preferred_lft forever
 inet6 fe80::20c:29ff:fe59:caca/64 scope link
       valid_lft forever preferred_lft forever
user@net2:~$
```

使用较旧的`ifconfig`工具的优势在于您可以同时看到 IPv4 和 IPv6 接口信息。当使用`ip`工具时，您需要通过传递`-6`标志来指定您希望看到 IPv6 信息。当我们在后面使用`ip`工具配置 IPv6 接口时，我们将看到这种情况是一样的。

在任一情况下，两台主机现在似乎都已经在它们的`eth0`接口上配置了 IPv6。但是，请注意，实际上我们定义了两个 IPv6 地址。您会注意到一个地址的范围是本地的，另一个地址的范围是全局的。在 IPv6 中，每个 IP 接口都被分配了全局和本地 IPv6 地址。本地范围的接口仅对其分配的链路上的通信有效，并且通常用于到达同一段上的相邻设备。在大多数情况下，链路本地地址是由主机自己动态确定的。这意味着几乎每个启用 IPv6 的接口都有一个链路本地 IPv6 地址，即使您没有在接口上专门配置全局 IPv6 地址。使用链路本地 IP 地址的数据包永远不会被路由器转发，这将限制它们在定义的段上。在我们的大部分讨论中，我们将专注于全局地址。

### 注意

任何对 IPv6 地址的进一步引用都是指全局范围的 IPv6 地址，除非另有说明。

由于我们的两台主机都在同一个子网上，我们应该能够使用 IPv6 从一台服务器到达另一台服务器：

```
user@net1:~$ **ping6 2003:ab11::2 -c 2
PING 2003:ab11::2(2003:ab11::2) 56 data bytes
64 bytes from 2003:ab11::2: icmp_seq=1 ttl=64 time=0.422 ms
64 bytes from 2003:ab11::2: icmp_seq=2 ttl=64 time=0.401 ms
--- 2003:ab11::2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.401/0.411/0.422/0.022 ms
user@net1:~$
```

请注意，我们使用`ping6`工具而不是标准的 ping 工具来验证 IPv6 的可达性。

我们想要检查的最后一件事是邻居发现表。IPv6 的另一个重大变化是它不使用 ARP 来查找 IP 端点的硬件或 MAC 地址。这样做的主要原因是 IPv6 不支持广播流量。ARP 依赖广播来工作，因此不能在 IPv6 中使用。相反，IPv6 使用邻居发现，它利用多播。

话虽如此，当排除本地网络故障时，您需要查看邻居发现表，而不是 ARP 表。为此，我们可以使用熟悉的`iproute2`工具集：

```
user@net1:~$ **ip -6 neighbor show
fe80::20c:29ff:fe59:caca dev eth0 lladdr 00:0c:29:59:ca:ca DELAY
2003:ab11::2 dev eth0 lladdr 00:0c:29:59:ca:ca REACHABLE
user@net1:~$
```

与 ARP 表类似，邻居表向我们显示了我们希望到达的 IPv6 地址的硬件或 MAC 地址。请注意，与之前一样，我们向`ip`命令传递了`-6`标志，告诉它我们需要 IPv6 信息。

现在我们已经建立了基本的连接性，让我们在每个主机上添加一个新的 IPv6 接口。为此，我们几乎可以按照添加 IPv4 接口时所做的相同步骤进行操作。例如，添加虚拟接口几乎是相同的：

```
user@net1:~$ sudo ip link add ipv6_dummy type dummy
user@net1:~$ sudo ip -6 address add 2003:cd11::1/64 dev ipv6_dummy
user@net1:~$ sudo ip link set ipv6_dummy up
```

请注意，唯一的区别是我们需要再次传递`-6`标志，告诉`iproute2`我们正在指定一个 IPv6 地址。在其他方面，配置与我们在 IPv4 中所做的方式完全相同。让我们也在第二个主机上配置另一个虚拟接口：

```
user@net2:~$ sudo ip link add ipv6_dummy type dummy
user@net2:~$ sudo ip -6 address add 2003:ef11::1/64 dev ipv6_dummy
user@net2:~$ sudo ip link set ipv6_dummy up
```

此时，我们的拓扑现在如下所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_10_02.jpg)

现在让我们检查每个主机的 IPv6 路由表。与之前一样，我们也可以使用`iproute2`工具来检查 IPv6 路由表：

```
user@net1:~$ ip -6 route
2003:ab11::/64 dev eth0  proto kernel  metric 256  pref medium
2003:cd11::/64 dev ipv6_dummy  proto kernel  metric 256  pref medium
fe80::/64 dev eth0  proto kernel  metric 256  pref medium
fe80::/64 dev ipv6_dummy  proto kernel  metric 256  pref medium
user@net1:~$

user@net2:~$ ip -6 route
2003:ab11::/64 dev eth0  proto kernel  metric 256  pref medium
2003:ef11::/64 dev ipv6_dummy  proto kernel  metric 256  pref medium
fe80::/64 dev eth0  proto kernel  metric 256  pref medium
fe80::/64 dev ipv6_dummy  proto kernel  metric 256  pref medium
user@net2:~$
```

正如我们所看到的，每个主机都知道自己直接连接的接口，但不知道其他主机的虚拟接口。为了使任何一个主机能够到达其他主机的虚拟接口，我们需要进行路由。由于这些主机是直接连接的，可以通过添加默认的 IPv6 路由来解决。每个默认路由将引用另一个主机作为下一跳。虽然这是可行的，但让我们改为向每个主机添加特定路由，引用虚拟接口所在的网络：

```
user@net1:~$ sudo ip -6 route add **2003:ef11::/64 via 2003:ab11::2
user@net2:~$ sudo ip -6 route add **2003:cd11::/64 via 2003:ab11::1

```

添加这些路由后，任何一个主机都应该能够到达其他主机的`ipv6_dummy`接口：

```
user@net1:~$ **ping6 2003:ef11::1 -c 2
PING 2003:ef11::1(2003:ef11::1) 56 data bytes
64 bytes from 2003:ef11::1: icmp_seq=1 ttl=64 time=0.811 ms
64 bytes from 2003:ef11::1: icmp_seq=2 ttl=64 time=0.408 ms
--- 2003:ef11::1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.408/0.609/0.811/0.203 ms
user@net1:~$
```

### 注意

您可能会注意到，只在单个主机上添加一个路由就可以使该主机到达另一个主机上的虚拟接口。这是因为我们只需要路由来将流量从发起主机上移出。流量将由主机的 `eth0` 接口（`2003:ab11::/64`）发出，而另一个主机知道如何到达它。如果 ping 是从虚拟接口发出的，您需要这两个路由才能使其正常工作。

现在我们已经配置并验证了基本的连接性，让我们迈出最后一步，使用网络命名空间重建这些接口。为此，让我们首先清理虚拟接口，因为我们将在命名空间内重用这些 IPv6 子网：

```
user@net1:~$ sudo ip link del dev ipv6_dummy
user@net2:~$ sudo ip link del dev ipv6_dummy
```

我们要配置的配置如下：

![操作步骤…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_10_03.jpg)

虽然与上一个配置非常相似，但有两个主要区别。您会注意到我们现在使用网络命名空间来封装新接口。这样做，我们已经为 VETH 对的一端配置了新接口的 IPv6 地址。VETH 对的另一端位于默认网络命名空间中的主机上。

### 注意

如果您对一些 Linux 网络构造不太熟悉，请查看第一章中的 *Linux 网络构造*，在那里我们会更详细地讨论命名空间和 VETH 接口。

要进行配置，我们将应用以下配置：

添加一个名为 `net1_ns` 的新网络命名空间：

```
user@net1:~$ sudo ip netns add net1_ns
```

创建一个名为 `host_veth1` 的 VETH 对，并将另一端命名为 `ns_veth1`：

```
user@net1:~$ sudo ip link add host_veth1 type veth peer name ns_veth1
```

将 VETH 对的命名空间端移入命名空间：

```
user@net1:~$ sudo ip link set dev ns_veth1 netns net1_ns
```

在命名空间内，给 VETH 接口分配一个 IP 地址：

```
user@net1:~$ sudo ip netns exec net1_ns ip -6 address \
add 2003:cd11::2/64 dev ns_veth1
```

在命名空间内，启动接口：

```
user@net1:~$ sudo ip netns exec net1_ns ip link set ns_veth1 up
```

在命名空间内，添加一个路由以到达另一个主机上的命名空间：

```
user@net1:~$ sudo ip netns exec net1_ns ip -6 route \
add 2003:ef11::/64 via 2003:cd11::1
```

给 VETH 对的主机端分配一个 IP 地址：

```
user@net1:~$ sudo ip -6 address add 2003:cd11::1/64 dev host_veth1
```

启动 VETH 接口的主机端：

```
user@net1:~$ sudo ip link set host_veth1 up
```

### 注意

请注意，我们只在命名空间内添加了一个路由以到达另一个命名空间。我们没有在 Linux 主机上添加相同的路由。这是因为我们之前已经在配方中添加了这个路由，以便到达虚拟接口。如果您删除了该路由，您需要将其添加回来才能使其正常工作。

我们现在必须在第二个主机上执行类似的配置：

```
user@net2:~$ sudo ip netns add net2_ns
user@net2:~$ sudo ip link add host_veth1 type veth peer name ns_veth1
user@net2:~$ sudo ip link set dev ns_veth1 netns net2_ns
user@net2:~$ sudo ip netns exec net2_ns ip -6 address add \
2003:ef11::2/64 dev ns_veth1
user@net2:~$ sudo ip netns exec net2_ns ip link set ns_veth1 up
user@net2:~$ sudo ip netns exec net2_ns ip -6 route add \
2003:cd11::/64 via 2003:ef11::1
user@net2:~$ sudo ip -6 address add 2003:ef11::1/64 dev host_veth1
user@net2:~$ sudo ip link set host_veth1 up
```

添加后，您应该能够验证每个命名空间是否具有到达其他主机命名空间所需的路由信息：

```
user@net1:~$ sudo ip netns exec net1_ns ip -6 route
2003:cd11::/64 dev ns_veth1  proto kernel  metric 256  pref medium
2003:ef11::/64 via 2003:cd11::1 dev ns_veth1  metric 1024  pref medium
fe80::/64 dev ns_veth1  proto kernel  metric 256  pref medium
user@net1:~$
user@net2:~$ sudo ip netns exec net2_ns ip -6 route
2003:cd11::/64 via 2003:ef11::1 dev ns_veth1  metric 1024  pref medium
2003:ef11::/64 dev ns_veth1  proto kernel  metric 256  pref medium
fe80::/64 dev ns_veth1  proto kernel  metric 256  pref medium
user@net2:~$
```

但是当我们尝试从一个命名空间到另一个命名空间时，连接失败：

```
user@net1:~$ **sudo ip netns exec net1_ns ping6 2003:ef11::2 -c 2
PING 2003:ef11::2(2003:ef11::2) 56 data bytes
--- 2003:ef11::2 ping statistics ---
2 packets transmitted, 0 received, **100% packet loss**, time 1007ms
user@net1:~$
```

这是因为我们现在正在尝试将 Linux 主机用作路由器。如果您回忆起早期章节，当我们希望 Linux 内核转发或路由数据包时，我们必须启用该功能。这是通过更改每个主机上的这两个内核参数来完成的：

```
user@net1:~$ sudo sysctl **net.ipv6.conf.default.forwarding=1
net.ipv6.conf.default.forwarding = 1
user@net1:~$ sudo sysctl **net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.forwarding = 1
```

### 注意

请记住，以这种方式定义的设置在重新启动时不会持久保存。

一旦在两个主机上进行了这些设置，您的 ping 现在应该开始工作：

```
user@net1:~$ **sudo ip netns exec net1_ns ping6 2003:ef11::2 -c 2
PING 2003:ef11::2(2003:ef11::2) 56 data bytes
64 bytes from 2003:ef11::2: icmp_seq=1 ttl=62 time=0.540 ms
64 bytes from 2003:ef11::2: icmp_seq=2 ttl=62 time=0.480 ms
--- 2003:ef11::2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 0.480/0.510/0.540/0.030 ms
user@net1:~$
```

有趣的是，在启用内核中的 IPv6 转发后，检查主机上的邻居表：

```
user@net1:~$ ip -6 neighbor
2003:ab11::2 dev eth0 lladdr 00:0c:29:59:ca:ca router STALE
2003:cd11::2 dev host_veth1 lladdr a6:14:b5:39:da:96 STALE
fe80::20c:29ff:fe59:caca dev eth0 lladdr 00:0c:29:59:ca:ca router STALE
fe80::a414:b5ff:fe39:da96 dev host_veth1 lladdr a6:14:b5:39:da:96 STALE
user@net1:~$
```

您是否注意到另一个 Linux 主机的邻居条目有什么不同之处？现在，它的邻居定义中包含`router`标志。当 Linux 主机在内核中启用 IPv6 转发时，它会在该段上作为路由器进行广告。

# 启用 Docker 中的 IPv6 功能

Docker 中默认禁用 IPv6 功能。与我们之前审查的其他功能一样，要启用它需要在服务级别进行设置。一旦启用，Docker 将为与 Docker 关联的主机接口以及容器本身提供 IPv6 地址。

## 准备就绪

在这个示例中，我们将使用由两个 Docker 主机组成的小型实验室：

![准备就绪](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_10_04.jpg)

每个主机都有分配给其物理接口的 IPv4 地址和 IPv6 地址。您需要对每个主机进行网络配置更改的根级访问权限。假定已安装了 Docker，并且它是默认配置。

## 如何做…

如前所述，除非告知，Docker 不会为容器提供 IPv6 地址。要在 Docker 中启用 IPv6，我们需要向 Docker 服务传递一个服务级标志。

### 注意

如果您需要复习定义 Docker 服务级参数，请参阅第二章中的最后一个示例，*配置和监视 Docker 网络*，在那里我们讨论了在运行`systemd`的系统上配置这些参数。

除了启用 IPv6 功能，您还需要为`docker0`桥定义一个子网。为此，我们将修改 Docker 的`systemd`附加文件，并确保它具有以下选项：

+   在主机`docker1`上：

```
ExecStart=/usr/bin/dockerd --ipv6 --fixed-cidr-v6=2003:cd11::/64
```

+   在主机`docker2`上：

```
ExecStart=/usr/bin/dockerd --ipv6 --fixed-cidr-v6=2003:ef11::/64
```

如果我们应用此配置，在每个主机上重新加载`systemd`配置并重新启动 Docker 服务，我们应该会看到`docker0`桥已经从定义的 IPv6 CIDR 范围中获取了第一个可用的 IP 地址：

```
user@docker1:~$ ip -6 addr show dev docker0
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500
 inet6 2003:cd11::1/64 scope global tentative
       valid_lft forever preferred_lft forever
    inet6 fe80::1/64 scope link tentative
       valid_lft forever preferred_lft forever
user@docker1:~$

user@docker2:~$ ip -6 addr show dev docker0
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500
 inet6 2003:ef11::1/64 scope global tentative
       valid_lft forever preferred_lft forever
    inet6 fe80::1/64 scope link tentative
       valid_lft forever preferred_lft forever
user@docker2:~$
```

此时，我们的拓扑结构看起来很像第一个配方中的样子：

![操作步骤](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_10_05.jpg)

Docker 将为其创建的每个容器分配一个 IPv6 地址和一个 IPv4 地址。让我们在第一个主机上启动一个容器，看看我的意思是什么：

```
user@docker1:~$ **docker run -d --name=web1 jonlangemak/web_server_1
50d522d176ebca2eac0f7e826ffb2e36e754ce27b3d3b4145aa8a11c6a13cf15
user@docker1:~$
```

请注意，我们没有向容器传递`-P`标志来发布容器暴露的端口。如果我们在本地测试，我们可以验证主机可以从容器的 IPv4 和 IPv6 地址访问容器内的服务：

```
user@docker1:~$ docker exec web1 ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:02
 inet addr:172.17.0.2  Bcast:0.0.0.0  Mask:255.255.0.0
          inet6 addr: fe80::42:acff:fe11:2/64 Scope:Link
 inet6 addr: 2003:cd11::242:ac11:2/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:16 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:1792 (1.7 KB)  TX bytes:648 (648.0 B)

user@docker1:~$ **curl http://172.17.0.2
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">Web Server #1 - Running on port 80</span>
    </h1>
</body>
  </html>
user@docker1:~$ **curl -g http://[2003:cd11::242:ac11:2]
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">Web Server #1 - Running on port 80</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

### 注意

在使用带有 IPv6 地址的`curl`时，您需要将 IPv6 地址放在方括号中，然后通过传递`-g`标志告诉`curl`不要进行全局匹配。

正如我们所看到的，IPv6 地址的行为与 IPv4 地址的行为相同。随之而来，同一主机上的容器可以使用其分配的 IPv6 地址直接相互通信，跨过`docker0`桥。让我们在同一主机上启动第二个容器：

```
user@docker1:~$ docker run -d --name=web2 jonlangemak/web_server_2
```

快速验证将向我们证明这两个容器可以像预期的那样使用其 IPv6 地址直接相互通信：

```
user@docker1:~$ docker exec **web2** ip -6 addr show dev eth0
10: eth0@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 **2003:cd11::242:ac11:3/64** scope global nodad
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:3/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
user@docker1:~$ **docker exec -it web1 curl -g \
http://[2003:cd11::242:ac11:3]
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #2 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

# 使用 IPv6 启用的容器

在上一个配方中，我们看到了 Docker 如何处理启用 IPv6 的容器的基本分配。到目前为止，我们看到的行为与之前章节中处理 IPv4 地址容器时所看到的行为非常相似。然而，并非所有网络功能都是如此。Docker 目前在 IPv4 和 IPv6 之间并没有完全的功能对等。特别是，正如我们将在这个配方中看到的，Docker 对于启用 IPv6 的容器并没有`iptables`（ip6tables）集成。在本章中，我们将回顾一些我们之前在仅启用 IPv4 的容器中访问过的网络功能，并看看在使用 IPv6 寻址时它们的表现如何。

## 准备工作

在这个配方中，我们将继续构建上一个配方中构建的实验室。您需要 root 级别的访问权限来对每个主机进行网络配置更改。假设 Docker 已安装，并且是默认配置。

## 操作步骤

如前所述，Docker 目前没有针对 IPv6 的主机防火墙，特别是 netfilter 或`iptables`的集成。这意味着我们以前依赖 IPv4 的几个功能在处理容器的 IPv6 地址时会有所不同。让我们从一些基本功能开始。在上一个示例中，我们看到了在连接到`docker0`桥接器的同一主机上的两个容器可以直接相互通信。

这种行为是预期的，并且在使用 IPv4 地址时的方式基本相同。如果我们想要阻止这种通信，我们可能会考虑在 Docker 服务中禁用**容器间通信**（**ICC**）。让我们更新主机`docker1`上的 Docker 选项，将 ICC 设置为`false`：

```
ExecStart=/usr/bin/dockerd --icc=false --ipv6 --fixed-cidr-v6=2003:cd11::/64
```

然后，我们可以重新加载`systemd`配置，重新启动 Docker 服务，并重新启动容器：

```
user@docker1:~$ **docker start web1
web1
user@docker1:~$ **docker start web2
web2
user@docker1:~$ docker exec web2 ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:03
 inet addr:172.17.0.3**  Bcast:0.0.0.0  Mask:255.255.0.0
          inet6 addr: fe80::42:acff:fe11:3/64 Scope:Link
 inet6 addr: 2003:cd11::242:ac11:3**/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:12 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:1128 (1.1 KB)  TX bytes:648 (648.0 B)

user@docker1:~$
user@docker1:~$ **docker exec -it web1 curl http://172.17.0.3
curl: (7) couldn't connect to host
user@docker1:~$ **docker exec -it web1 curl -g \
http://[2003:cd11::242:ac11:3]
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #2 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

正如我们所看到的，IPv4 尝试失败，随后的 IPv6 尝试成功。由于 Docker 没有管理与容器的 IPv6 地址相关的防火墙规则，因此没有任何阻止 IPv6 地址之间直接连接的内容。

由于 Docker 没有管理与 IPv6 相关的防火墙规则，您可能还会认为出站伪装和端口发布等功能也不再起作用。虽然这在某种意义上是正确的，即 Docker 不会创建 IPv6 相关的 NAT 规则和防火墙策略，但这并不意味着容器的 IPv6 地址无法从外部网络访问。让我们通过一个示例来向您展示我的意思。让我们在第二个 Docker 主机上启动一个容器：

```
user@docker2:~$ docker run -dP --name=web2 jonlangemak/web_server_2
5e2910c002db3f21aa75439db18e5823081788e69d1e507c766a0c0233f6fa63
user@docker2:~$
user@docker2:~$ docker port web2
80/tcp -> 0.0.0.0:32769
user@docker2:~$
```

请注意，当我们在主机`docker2`上运行容器时，我们传递了`-P`标志，告诉 Docker 发布容器的暴露端口。如果我们检查端口映射，我们可以看到主机选择了端口`32768`。请注意，端口映射指示 IP 地址为`0.0.0.0`，通常表示任何 IPv4 地址。让我们从另一个 Docker 主机执行一些快速测试，以验证工作和不工作的内容：

```
user@docker1:~$ **curl http://10.10.10.102:32769
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #2 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

如预期的那样，IPv4 端口映射起作用。通过利用`iptables` NAT 规则将端口`32769`映射到实际服务端口`80`，我们能够通过 Docker 主机的 IPv4 地址访问容器的服务。现在让我们尝试相同的示例，但使用主机的 IPv6 地址：

```
user@docker1:~$ **curl -g http://[2003:ab11::2]:32769
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #2 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

令人惊讶的是，这也起作用。您可能想知道这是如何工作的，考虑到 Docker 不管理或集成任何主机 IPv6 防火墙策略。答案实际上非常简单。如果我们查看第二个 Docker 主机的开放端口，我们会看到有一个绑定到端口`32769`的`docker-proxy`服务：

```
user@docker2:~$ sudo netstat -plnt
…<output removed for brevity>…
Active Internet connections (only servers)
Local Address   Foreign Address         State       PID/Program name
0.0.0.0:22      0.0.0.0:*               LISTEN      1387/sshd
127.0.0.1:6010  0.0.0.0:*               LISTEN      3658/0
:::22           :::*                    LISTEN      1387/sshd
::1:6010        :::*                    LISTEN      3658/0
:::32769        :::*                    LISTEN      2390/docker-proxy
user@docker2:~$
```

正如我们在前几章中看到的，`docker-proxy`服务促进了容器之间和发布端口的连接。为了使其工作，`docker-proxy`服务必须绑定到容器发布的端口。请记住，监听所有 IPv4 接口的服务使用`0.0.0.0`的语法来表示所有 IPv4 接口。类似地，IPv6 接口使用`:::`的语法来表示相同的事情。您会注意到`docker-proxy`端口引用了所有 IPv6 接口。尽管这可能因操作系统而异，但绑定到所有 IPv6 接口也意味着绑定到所有 IPv4 接口。也就是说，前面的`docker-proxy`服务实际上正在监听所有主机的 IPv4 和 IPv6 接口。

### 注意

请记住，`docker-proxy`通常不用于入站服务。这些依赖于`iptables` NAT 规则将发布的端口映射到容器。但是，在这些规则不存在的情况下，主机仍然在其所有接口上监听端口`32769`的流量。

这样做的最终结果是，尽管没有 IPv6 NAT 规则，我仍然能够通过 Docker 主机接口访问容器服务。以这种方式，具有 IPv6 的发布端口仍然有效。但是，只有在使用`docker-proxy`时才有效。尽管这种操作模式仍然是默认的，但打算在 hairpin NAT 的支持下移除。我们可以通过将`--userland-proxy=false`参数传递给 Docker 作为服务级选项来在 Docker 主机上启用 hairpin NAT。这样做将阻止这种 IPv6 端口发布方式的工作。

最后，缺乏防火墙集成也意味着我们不再支持出站伪装功能。在 IPv4 中，这个功能允许容器与外部网络通信，而不必担心路由或 IP 地址重叠。离开主机的容器流量总是隐藏在主机 IP 接口之一的后面。然而，这并不是一个强制性的配置。正如我们在前几章中看到的，您可以非常容易地禁用出站伪装功能，并为`docker0`桥接分配一个可路由的 IP 地址和子网。只要外部或外部网络知道如何到达该子网，容器就可以非常容易地拥有一个独特的可路由 IP 地址。

IPv6 出现的一个原因是 IPv4 地址的迅速枯竭。IPv4 中的 NAT 作为一个相当成功的，尽管同样麻烦的临时缓解了地址枯竭问题。这意味着许多人认为，我们不应该在 IPv6 方面实施任何形式的 NAT。相反，所有 IPv6 前缀都应该是本地可路由和可达的，而不需要 IP 转换的混淆。缺乏 IPv6 防火墙集成，直接将 IPv6 流量路由到每个主机是 Docker 实现跨多个 Docker 主机和外部网络可达性的当前手段。这要求每个 Docker 主机使用唯一的 IPv6 CIDR 范围，并且 Docker 主机知道如何到达所有其他 Docker 主机定义的 CIDR 范围。虽然这通常需要物理网络具有网络可达性信息，在我们简单的实验室示例中，每个主机只需要对其他主机的 CIDR 添加静态路由。就像我们在第一个配方中所做的那样，我们将在每个主机上添加一个 IPv6 路由，以便两者都知道如何到达另一个`docker0`桥接的 IPv6 子网：

```
user@docker1:~$ sudo ip -6 route add 2003:ef11::/64 via 2003:ab11::2
user@docker2:~$ sudo ip -6 route add 2003:cd11::/64 via 2003:ab11::1
```

添加路由后，每个 Docker 主机都知道如何到达另一个主机的 IPv6 `docker0`桥接子网：

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_10_06.jpg)

如果我们现在检查，我们应该在每个主机上的容器之间有可达性：

```
user@docker2:~$ docker exec web2 ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:02
 inet addr:172.17.0.2**  Bcast:0.0.0.0  Mask:255.255.0.0
          inet6 addr: fe80::42:acff:fe11:2/64 Scope:Link
 inet6 addr: 2003:ef11::242:ac11:2/64** Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:43 errors:0 dropped:0 overruns:0 frame:0
          TX packets:34 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:3514 (3.5 KB)  TX bytes:4155 (4.1 KB)

user@docker2:~$
user@docker1:~$ **docker exec -it web1 curl -g http://[2003:ef11::242:ac11:2]
<body>
  <html>
    <h1><span style="color:#FF0000;font-size:72px;">**Web Server #2 - Running on port 80**</span>
    </h1>
</body>
  </html>
user@docker1:~$
```

正如我们所看到的，主机`docker1`上的容器能够成功地直接路由到运行在主机`docker2`上的容器。只要每个 Docker 主机具有适当的路由信息，容器就能够直接路由到彼此。

这种方法的缺点是容器现在是一个完全暴露的网络端点。我们不再能够通过 Docker 发布的端口仅暴露某些端口到外部网络的优势。如果您希望确保仅在 IPv6 接口上暴露某些端口，那么用户态代理可能是您目前的最佳选择。在设计围绕 IPv6 连接的服务时，请记住这些选项。

# 配置 NDP 代理

正如我们在上一个教程中看到的，Docker 中 IPv6 支持的一个主要区别是缺乏防火墙集成。没有这种集成，我们失去了出站伪装和完整端口发布功能。虽然这在所有情况下可能并非必要，但当不使用时会失去一定的便利因素。例如，在仅运行 IPv4 模式时，管理员可以安装 Docker 并立即将容器连接到外部网络。这是因为容器只能通过 Docker 主机的 IP 地址进行入站（发布端口）和出站（伪装）连接。这意味着无需通知外部网络有关额外子网的信息，因为外部网络只能看到 Docker 主机的 IP 地址。在 IPv6 模型中，外部网络必须知道容器子网才能路由到它们。在本章中，我们将讨论如何配置 NDP 代理作为解决此问题的方法。

## 准备工作

在本教程中，我们将使用以下实验拓扑：

![准备工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_10_07.jpg)

您需要 root 级别的访问权限来对每个主机进行网络配置更改。假设 Docker 已安装，并且是默认配置。

## 如何做…

前面的拓扑图显示我们的主机是双栈连接到网络的，但是 Docker 还没有配置为使用 IPv6。就像我们在上一个教程中看到的那样，配置 Docker 以支持 IPv6 通常意味着在外部网络上配置路由，以便它知道如何到达您为`docker0`桥定义的 IPv6 CIDR。然而，假设一会儿这是不可能的。假设您无法控制外部网络，这意味着您无法向其他网络端点广告或通知有关 Docker 主机上任何新定义的 IPv6 子网。

假设虽然您无法广告任何新定义的 IPv6 网络，但您可以在现有网络中保留额外的 IPv6 空间。例如，主机当前在`2003:ab11::/64`网络中定义了接口。如果我们划分这个空间，我们可以将其分割成四个`/66`网络：

+   `2003:ab11::/66`

+   `2003:ab11:0:0:4000::/66`

+   `2003:ab11:0:0:8000::/66`

+   `2003:ab11:0:0:c000::/66`

假设我们被允许为我们的使用保留最后两个子网。我们现在可以在 Docker 中启用 IPv6，并将这两个网络分配为 IPv6 CIDR 范围。以下是每个 Docker 主机的配置选项：

+   `docker1`

```
ExecStart=/usr/bin/dockerd --ipv6 --fixed-cidr-v6=2003:ab11:0:0:8000::/66
```

+   `docker2`

```
ExecStart=/usr/bin/dockerd --ipv6 --fixed-cidr-v6=2003:ab11:0:0:c000::/66
```

将新配置加载到`systemd`中并重新启动 Docker 服务后，我们的实验室拓扑现在看起来是这样的：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-net-cb/img/5453_10_08.jpg)

让我们在两个主机上启动一个容器：

```
user@docker1:~$ docker run -d --name=web1 jonlangemak/web_server_1
user@docker2:~$ docker run -d --name=web2 jonlangemak/web_server_2
```

现在确定`web1`容器的分配的 IPv6 地址：

```
user@docker1:~$ docker exec web1 ip -6 addr show dev eth0
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 **2003:ab11::8000:242:ac11:2/66** scope global nodad
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:2/64 scope link
       valid_lft forever preferred_lft forever
user@docker1:~$
```

现在，让我们尝试从`web2`容器到达该容器：

```
user@docker2:~$ **docker exec -it web2 ping6 \
2003:ab11::8000:242:ac11:2**  -c 2
PING 2003:ab11::8000:242:ac11:2 (2003:ab11::8000:242:ac11:2): 48 data bytes
56 bytes from 2003:ab11::c000:0:0:1: Destination unreachable: Address unreachable
56 bytes from 2003:ab11::c000:0:0:1: Destination unreachable: Address unreachable
--- 2003:ab11::8000:242:ac11:2 ping statistics ---
2 packets transmitted, 0 packets received, **100% packet loss
user@docker2:~$
```

这失败是因为 Docker 主机认为目标地址直接连接到它们的`eth0`接口。当`web2`容器尝试连接时，会发生以下操作：

+   容器进行路由查找，并确定地址`2003:ab11::8000:242:ac11:2`不在其本地子网`2003:ab11:0:0:c000::1/66`内，因此将流量转发到其默认网关（`docker0`桥接口）

+   主机接收流量并进行路由查找，确定`2003:ab11::8000:242:ac11:2`的目标地址落在其本地子网`2003:ab11::/64`（`eth0`）内，并使用 NDP 尝试找到具有该目标 IP 地址的主机

+   主机对此查询没有响应，流量失败

我们可以通过检查`docker2`主机的 IPv6 邻居表来验证这一点：

```
user@docker2:~$ ip -6 neighbor show
fe80::20c:29ff:fe50:b8cc dev eth0 lladdr 00:0c:29:50:b8:cc STALE
2003:ab11::c000:242:ac11:2 dev docker0 lladdr 02:42:ac:11:00:02 REACHABLE
2003:ab11::8000:242:ac11:2 dev eth0  FAILED
fe80::42:acff:fe11:2 dev docker0 lladdr 02:42:ac:11:00:02 REACHABLE
user@docker2:~$
```

按照正常的路由逻辑，一切都按预期工作。然而，IPv6 有一个叫做 NDP 代理的功能，可以帮助解决这个问题。熟悉 IPv4 中代理 ARP 的人会发现 NDP 代理提供了类似的功能。基本上，NDP 代理允许主机代表另一个端点回答邻居请求。在我们的情况下，我们可以告诉两个 Docker 主机代表容器回答。为了做到这一点，我们首先需要在主机上启用 NDP 代理。这是通过启用内核参数`net.ipv6.conf.eth0.proxy_ndp`来完成的，如下面的代码所示：

```
user@docker1:~$ sudo sysctl net.ipv6.conf.eth0.proxy_ndp=1
net.ipv6.conf.eth0.proxy_ndp = 1
user@docker1:~$
user@docker2:~$ sudo sysctl net.ipv6.conf.eth0.proxy_ndp=1
net.ipv6.conf.eth0.proxy_ndp = 1
user@docker2:~$
```

### 注意

请记住，以这种方式定义的设置在重启后不会持久保存。

一旦启用了这个功能，我们需要手动告诉每个主机要回答哪个 IPv6 地址。我们通过向每个主机的邻居表添加代理条目来实现这一点。在前面的例子中，我们需要为源容器和目标容器都这样做，以便允许双向流量。首先，在主机`docker1`上为目标添加条目：

```
user@docker1:~$ sudo ip -6 neigh add proxy \
2003:ab11::8000:242:ac11:2** dev eth0
```

然后，确定`web2`容器的 IPv6 地址，它将作为流量的源，并在主机`docker2`上为其添加代理条目：

```
user@docker2:~$ docker exec web2 ip -6 addr show dev eth0
6: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet6 **2003:ab11::c000:242:ac11:2/66** scope global nodad
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:2/64 scope link
       valid_lft forever preferred_lft forever
user@docker2:~$
user@docker2:~$ sudo ip -6 neigh add proxy \
2003:ab11::c000:242:ac11:2** dev eth0
```

这将告诉每个 Docker 主机代表容器回复邻居请求。Ping 测试现在应该按预期工作：

```
user@docker2:~$ **docker exec -it web2 ping6 \
2003:ab11::8000:242:ac11:2** -c 2
PING 2003:ab11::8000:242:ac11:2 (2003:ab11::8000:242:ac11:2): 48 data bytes
56 bytes from 2003:ab11::8000:242:ac11:2: icmp_seq=0 ttl=62 time=0.462 ms
56 bytes from 2003:ab11::8000:242:ac11:2: icmp_seq=1 ttl=62 time=0.660 ms
--- 2003:ab11::8000:242:ac11:2 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.462/0.561/0.660/0.099 ms
user@docker2:~$
```

我们应该在每个主机上看到相关的邻居条目：

```
user@docker1:~$ ip -6 neighbor show
fe80::20c:29ff:fe7f:3d64 dev eth0 lladdr 00:0c:29:7f:3d:64 router REACHABLE
2003:ab11::8000:242:ac11:2 dev docker0 lladdr 02:42:ac:11:00:02 REACHABLE
fe80::42:acff:fe11:2 dev docker0 lladdr 02:42:ac:11:00:02 DELAY
2003:ab11::c000:242:ac11:2 dev eth0 lladdr 00:0c:29:7f:3d:64 REACHABLE
user@docker1:~$
user@docker2:~$ ip -6 neighbor show
fe80::42:acff:fe11:2 dev docker0 lladdr 02:42:ac:11:00:02 REACHABLE
2003:ab11::c000:242:ac11:2 dev docker0 lladdr 02:42:ac:11:00:02 REACHABLE
fe80::20c:29ff:fe50:b8cc dev eth0 lladdr 00:0c:29:50:b8:cc router REACHABLE
2003:ab11::8000:242:ac11:2 dev eth0 lladdr 00:0c:29:50:b8:cc REACHABLE
user@docker2:~$
```

就像代理 ARP 一样，NDP 代理是通过主机在邻居发现请求中提供自己的 MAC 地址来工作的。我们可以看到，在这两种情况下，邻居表中的 MAC 地址实际上是每个主机的`eth0` MAC 地址。

```
user@docker1:~$ ip link show dev eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether **00:0c:29:50:b8:cc** brd ff:ff:ff:ff:ff:ff
user@docker1:~$
user@docker2:~$ ip link show dev eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether **00:0c:29:7f:3d:64** brd ff:ff:ff:ff:ff:ff
user@docker2:~$
```

这种方法在无法将 Docker IPv6 子网广告传播到外部网络的情况下效果相当不错。然而，它依赖于每个希望代理的 IPv6 地址的单独代理条目。对于每个生成的容器，您都需要生成一个额外的 IPv6 代理地址。

# 用户定义的网络和 IPv6

就像我们在 IPv4 中看到的那样，用户定义的网络可以利用 IPv6 寻址。也就是说，所有与网络相关的参数都与 IPv4 和 IPv6 相关。在本章中，我们将介绍如何定义用户定义的 IPv6 网络，并演示一些相关的配置选项。

## 准备工作

在这个示例中，我们将使用一个单独的 Docker 主机。假设 Docker 已安装并处于默认配置。不需要使用`--ipv6`服务级参数启用 Docker 服务，以便在用户定义的网络上使用 IPv6 寻址。

## 如何做到这一点...

在使用用户定义的网络时，我们可以为 IPv4 和 IPv6 定义配置。此外，当我们运行容器时，我们可以指定它们的 IPv4 和 IPv6 地址。为了演示这一点，让我们首先定义一个具有 IPv4 和 IPv6 寻址的用户定义网络：

```
user@docker1:~$ docker network create -d bridge \
--subnet 2003:ab11:0:0:c000::/66 --subnet 192.168.127.0/24 \
--ipv6 ipv6_bridge
```

这个命令的语法应该对你来说很熟悉，来自第三章*用户定义的网络*，在那里我们讨论了用户定义的网络。然而，有几点需要指出。

首先，您会注意到我们定义了`--subnet`参数两次。这样做，我们既定义了一个 IPv4 子网，也定义了一个 IPv6 子网。当定义 IPv4 和 IPv6 地址时，`--gateway`和`--aux-address`字段可以以类似的方式使用。其次，我们定义了一个选项来在此网络上启用 IPv6。如果您不定义此选项以启用 IPv6，则主机的网关接口将不会被定义。

一旦定义好，让我们在网络上启动一个容器，看看我们的配置是什么样的：

```
user@docker1:~$ docker run -d --name=web1 --net=ipv6_bridge \
--ip 192.168.127.10 --ip6 2003:ab11::c000:0:0:10 \
jonlangemak/web_server_1
```

这个语法对你来说也应该很熟悉。请注意，我们指定这个容器应该是用户定义网络`ipv6_bridge`的成员。这样做，我们还可以使用`--ip`和`--ip6`参数为容器定义 IPv4 和 IPv6 地址。

如果我们检查网络，我们应该看到容器附加以及与网络定义以及容器网络接口相关的所有相关信息：

```
user@docker1:~$ docker network inspect ipv6_bridge
[
    {
        "Name": "ipv6_bridge",
        "Id": "0c6e760998ea6c5b99ba39f3c7ce63b113dab2276645e5fb7a2207f06273401a",
        "Scope": "local",
        "Driver": "**bridge**",
        "IPAM": {
            "Driver": "default",
            "Options": {},
            "Config": [
                {
                    "Subnet": "**192.168.127.0/24**"
                },
                {
                    "Subnet": "**2003:ab11:0:0:c000::/66**"
                }
            ]
        },
        "Containers": {
            "38e7ac1a0d0ce849a782c5045caf770c3310aca42e069e02a55d0c4a601e6b5a": {
                "Name": "web1",
                "EndpointID": "a80ac4b00d34d462ed98084a238980b3a75093591630b5832f105d400fabb4bb",
                "MacAddress": "02:42:c0:a8:7f:0a",
                "IPv4Address": "**192.168.127.10/24**",
                "IPv6Address": "**2003:ab11::c000:0:0:10/66**"
            }
        },
        "Options": {
            "**com.docker.network.enable_ipv6": "true"
        }
    }
]
user@docker1:~$
```

通过检查主机的网络配置，我们应该看到已创建了一个与这些网络匹配的新桥：

```
user@docker1:~$ ip addr show
…<Additional output removed for brevity>… 
9: br-0b2efacf6f85: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:09:bc:9f:77 brd ff:ff:ff:ff:ff:ff
    inet **192.168.127.1/24** scope global br-0b2efacf6f85
       valid_lft forever preferred_lft forever
    inet6 **2003:ab11::c000:0:0:1/66** scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::42:9ff:febc:9f77/64 scope link
       valid_lft forever preferred_lft forever
    inet6 fe80::1/64 scope link
       valid_lft forever preferred_lft forever
…<Additional output removed for brevity>…
user@docker1:~$ 
```

如果我们检查容器本身，我们会注意到这些接口是这个网络上的容器将用于其 IPv4 和 IPv6 默认网关的接口：

```
user@docker1:~$ docker exec web1 **ip route
default via 192.168.127.1 dev eth0
192.168.127.0/24 dev eth0  proto kernel  scope link  src 192.168.127.10
user@docker1:~$ docker exec web1 **ip -6 route
2003:ab11:0:0:c000::/66 dev eth0  proto kernel  metric 256
fe80::/64 dev eth0  proto kernel  metric 256
default via 2003:ab11::c000:0:0:1 dev eth0  metric 1024
user@docker1:~$
```

就像默认网络模式一样，用户定义的网络不支持主机防火墙集成，以支持出站伪装或入站端口发布。关于 IPv6 的连接，主机内外的情况与`docker0`桥相同，需要原生路由 IPv6 流量。

您还会注意到，如果您在主机上启动第二个容器，嵌入式 DNS 将同时适用于 IPv4 和 IPv6 寻址。

```
user@docker1:~$ docker run -d --name=web2 --net=ipv6_bridge \
jonlangemak/web_server_1
user@docker1:~$
user@docker1:~$ **docker exec -it web2 ping web1 -c 2
PING web1 (192.168.127.10): 48 data bytes
56 bytes from 192.168.127.10: icmp_seq=0 ttl=64 time=0.113 ms
56 bytes from 192.168.127.10: icmp_seq=1 ttl=64 time=0.111 ms
--- web1 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.111/0.112/0.113/0.000 ms
user@docker1:~$ 
user@docker1:~$ **docker exec -it web2 ping6 web1 -c 2
PING web1 (2003:ab11::c000:0:0:10): 48 data bytes
56 bytes from web1.ipv6_bridge: icmp_seq=0 ttl=64 time=0.113 ms
56 bytes from web1.ipv6_bridge: icmp_seq=1 ttl=64 time=0.127 ms
--- web1 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.113/0.120/0.127/0.000 ms
user@docker1:~$
```
