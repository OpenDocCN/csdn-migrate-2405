# Docker 部署手册（二）

> 原文：[`zh.annas-archive.org/md5/0E809A4AEE99AC7378E63C4191A037CF`](https://zh.annas-archive.org/md5/0E809A4AEE99AC7378E63C4191A037CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：保持数据持久性

在本章中，我们将介绍如何通过涵盖 Docker 卷的所有内容来保持您的重要数据持久、安全并独立于您的容器。我们将涵盖各种主题，包括以下内容：

+   Docker 镜像内部

+   部署您自己的存储库实例

+   瞬态存储

+   持久存储

+   绑定挂载

+   命名卷

+   可移动卷

+   用户和组 ID 处理

虽然我们不会涵盖所有可用的存储选项，特别是那些特定于编排工具的选项，但本章应该让您更好地了解 Docker 如何处理数据，以及您可以采取哪些措施来确保数据被保持在您想要的方式。

# Docker 镜像内部

为了更好地理解为什么我们需要持久性数据，我们首先需要详细了解 Docker 如何处理容器层。我们在之前的章节中已经详细介绍了这个主题，但在这里，我们将花一些时间来了解底层发生了什么。我们将首先讨论 Docker 目前如何处理容器内部的写入数据。

# 镜像的分层方式

正如我们之前所介绍的，Docker 将组成镜像的数据存储在一组离散的只读文件系统层中，当您构建镜像时，这些层会堆叠在一起。对文件系统所做的任何更改都会像透明幻灯片一样堆叠在一起，以创建完整的树，任何具有更新内容的文件（包括完全删除的文件）都会用新层遮盖旧的文件。我们以前对此的理解深度可能已经足够用于基本的容器处理，但对于高级用法，我们需要了解数据的全部内部处理方式。

当您使用相同的基础镜像启动多个容器时，它们都会被赋予与原始镜像相同的一组文件系统层，因此它们从完全相同的文件系统历史开始（除了任何挂载的卷或变量），这是我们所期望的。然而，在启动过程中，会在镜像顶部添加一个额外的可写层，该层会保留容器内部写入的任何数据：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/29fbb07c-b4ce-4194-96e6-3a3cb9968a06.png)

正如您所期望的那样，任何新文件都将写入此顶层，但是这个层实际上不是与其他层相同的类型，而是特殊的**写时复制**（CoW）类型。如果您在容器中写入的文件已经是底层层之一的一部分，Docker 将在新层中对其进行复制，掩盖旧文件，并从那时起，如果您读取或写入该文件，CoW 层将返回其内容。

如果您在不尝试保存这个新的 CoW 层或不使用卷的情况下销毁此容器，就像我们之前在不同的上下文中经历过的那样，这个可写层将被删除，并且容器写入文件系统的所有数据将被有效删除。实际上，如果您通常将容器视为具有薄且可写的 CoW 层的镜像，您会发现这种分层系统是多么简单而有效。

# 持久化可写的 CoW 层

在某个时候，您可能希望保存可写的容器层，以便以后用作常规镜像。虽然强烈不建议这种类型的镜像拼接，我大多数情况下也会同意，但您可能会发现在其他方式无法调查容器代码时，它可以为您提供一个宝贵的调试工具。要从现有容器创建镜像，有`docker commit`命令：

```
$ docker commit --help

Usage:  docker commit [OPTIONS] CONTAINER [REPOSITORY[:TAG]]

Create a new image from a container's changes

Options:
 -a, --author string    Author (e.g., "John Hannibal Smith <hannibal@a-team.com>")
 -c, --change list      Apply Dockerfile instruction to the created image
 --help             Print usage
 -m, --message string   Commit message
 -p, --pause            Pause container during commit (default true)
```

如您所见，我们只需要一些基本信息，Docker 会处理其余的部分。我们自己试一下如何：

```
$ # Run a new NGINX container and add a new file to it
$ docker run -d nginx:latest
2020a3b1c0fdb83c1f70c13c192eae25e78ca8288c441d753d5b42461727fa78
$ docker exec -it \
              2020a3b1 \
              /bin/bash -c "/bin/echo test > /root/testfile"

$ # Make sure that the file is in /root
$ docker exec -it \
              2020a3b1 \
              /bin/ls /root
testfile

$ # Check what this container's base image is so that we can see changes
$ docker inspect 2020a3b1 | grep Image
 "Image": "sha256:b8efb18f159bd948486f18bd8940b56fd2298b438229f5bd2bcf4cedcf037448",
 "Image": "nginx:latest",

$ # Commit our changes to a new image called "new_nginx_image"
$ docker commit -a "Author Name <author@site.com>" \
                -m "Added a test file" \
                2020a3b1 new_nginx_image
sha256:fda147bfb46277e55d9edf090c5a4afa76bc4ca348e446ca980795ad4160fc11

$ # Clean up our original container
$ docker stop 2020a3b1 && docker rm 2020a3b1
2020a3b1
2020a3b1

$ # Run this new image that includes the custom file
$ docker run -d new_nginx_image
16c5835eef14090e058524c18c9cb55f489976605f3d8c41c505babba660952d

$ # Verify that the file is there
$ docker exec -it \
              16c5835e \
              /bin/ls /root
testfile

$ # What about the content?
$ docker exec -it \
              16c5835e \
              /bin/cat /root/testfile
test

$ See what the new container's image is recorded as
$ docker inspect 16c5835e | grep Image
 "Image": "sha256:fda147bfb46277e55d9edf090c5a4afa76bc4ca348e446ca980795ad4160fc11",
 "Image": "new_nginx_image",

$ # Clean up
$ docker stop 16c5835e && docker rm 16c5835e
16c5835e
16c5835e
```

`docker commit -c`开关非常有用，并且像 Dockerfile 一样向镜像添加命令，并接受 Dockerfile 接受的相同指令，但由于这种形式很少使用，我们决定跳过它。如果您想了解更多关于这种特定形式和/或更多关于`docker commit`的信息，请随意在闲暇时探索[`docs.docker.com/engine/reference/commandline/commit/#commit-a-container-with-new-configurations`](https://docs.docker.com/engine/reference/commandline/commit/#commit-a-container-with-new-configurations)。

# 运行您自己的镜像注册表

在我们之前的章节中，在 Swarm 部署期间，我们收到了有关不使用注册表来存储我们的镜像的警告，而且理由充分。我们所做的所有工作都是基于我们的镜像仅对我们本地的 Docker 引擎可用，因此多个节点无法使用我们构建的任何镜像。对于绝对基本的设置，您可以使用 Docker Hub（[`hub.docker.com/`](https://hub.docker.com/)）作为托管公共镜像的选项，但由于几乎每个**虚拟私有云（VPC）**集群都使用其自己的内部私有注册表实例来确保安全、速度和隐私，我们将把 Docker Hub 作为一个探索的练习留给您，如果您想探索它，我们将介绍如何在这里运行我们自己的注册表。

Docker 最近推出了一个名为 Docker Cloud 的服务（[`cloud.docker.com/`](https://cloud.docker.com/)），其中包括私有注册表托管和持续集成，可能涵盖了小规模部署的相当多的用例，尽管目前该服务在单个私有存储库之外并不免费。一般来说，建立可扩展的基于 Docker 的集群的最受欢迎的方式是使用私有托管的注册表，因此我们将专注于这种方法，但要密切关注 Docker Cloud 正在开发的功能集，因为它可能填补了集群中的一些运营空白，您可以在构建基础设施的其他部分时推迟处理这些空白。

为了在本地托管注册表，Docker 提供了一个 Docker Registry 镜像（`registry:2`），您可以将其作为常规容器运行，包括以下后端：

+   `inmemory`：使用本地内存映射的临时镜像存储。这仅建议用于测试。

+   `filesystem`：使用常规文件系统树存储镜像。

+   `s3`，`azure`，`swift`，`oss`，`gcs`：云供应商特定的存储后端实现。

让我们部署一个具有本地文件系统后端的注册表，并看看它如何被使用。

警告！以下部分不使用 TLS 安全或经过身份验证的注册表配置。虽然在一些孤立的 VPC 中，这种配置可能是可以接受的，但通常情况下，您希望使用 TLS 证书来保护传输层，并添加某种形式的身份验证。幸运的是，由于 API 是基于 HTTP 的，您可以在不安全的注册表上使用反向代理的 Web 服务器，就像我们之前使用 NGINX 一样。由于证书需要被您的 Docker 客户端评估为“有效”，而这个过程对于几乎每个操作系统来说都是不同的，因此在大多数配置中，这里的工作通常不具备可移植性，这就是为什么我们跳过它的原因。

```
$ # Make our registry storage folder
$ mkdir registry_storage

$ # Start our registry, mounting the data volume in the container
$ # at the expected location. Use standard port 5000 for it.
$ docker run -d \
 -p 5000:5000 \
 -v $(pwd)/registry_storage:/var/lib/registry \
 --restart=always \
 --name registry \
 registry:2 
19e4edf1acec031a34f8e902198e6615fda1e12fb1862a35442ac9d92b32a637

$ # Pull a test image into our local Docker storage
$ docker pull ubuntu:latest
latest: Pulling from library/ubuntu
<snip>
Digest: sha256:2b9285d3e340ae9d4297f83fed6a9563493945935fc787e98cc32a69f5687641
Status: Downloaded newer image for ubuntu:latest

$ # "Tag our image" by marking it as something that is linked to our local registry
$ # we just started
$ docker tag ubuntu:latest localhost:5000/local-ubuntu-image

$ # Push our ubuntu:latest image into our local registry under "local-ubuntu-image" name
$ docker push localhost:5000/local-ubuntu-image
The push refers to a repository [localhost:5000/local-ubuntu-image]
<snip>
latest: digest: sha256:4b56d10000d71c595e1d4230317b0a18b3c0443b54ac65b9dcd3cac9104dfad2 size: 1357

$ # Verify that our image is in the right location in registry container
$ ls registry_storage/docker/registry/v2/repositories/
local-ubuntu-image

$ # Remove our images from our main Docker storage
$ docker rmi ubuntu:latest localhost:5000/local-ubuntu-image
Untagged: ubuntu:latest
Untagged: localhost:5000/local-ubuntu-image:latest
<snip>

$ # Verify that our Docker Engine doesn't have either our new image
$ # nor ubuntu:latest
$ docker images
REPOSITORY                TAG                 IMAGE ID            CREATED             SIZE

$ # Pull the image from our registry container to verify that our registry works
$ docker pull localhost:5000/local-ubuntu-image
Using default tag: latest
latest: Pulling from local-ubuntu-image
<snip>
Digest: sha256:4b56d10000d71c595e1d4230317b0a18b3c0443b54ac65b9dcd3cac9104dfad2
Status: Downloaded newer image for localhost:5000/local-ubuntu-image:latest

$ # Great! Verify that we have the image.
$ docker images
REPOSITORY                          TAG                 IMAGE ID            CREATED             SIZE
localhost:5000/local-ubuntu-image   latest              8b72bba4485f        23 hours ago        120MB
```

如您所见，使用本地注册表似乎非常容易！这里引入的唯一新事物可能需要在注册表本身之外进行一些覆盖的是`--restart=always`，它确保容器在意外退出时自动重新启动。标记是必需的，以将图像与注册表关联起来，因此通过执行`docker tag [<source_registry>/]<original_tag_or_id> [<target_registry>/]<new_tag>`，我们可以有效地为现有图像标签分配一个新标签，或者我们可以创建一个新标签。正如在这个小的代码片段中所示，源和目标都可以以可选的存储库位置为前缀，如果未指定，则默认为`docker.io`（Docker Hub）。

遗憾的是，根据个人经验，尽管这个例子让事情看起来很容易，但实际的注册表部署绝对不容易，因为外表可能具有欺骗性，而在使用它时需要牢记一些事情：

+   如果您使用不安全的注册表，要从不同的机器访问它，您必须将`"insecure-registries" : ["<ip_or_dns_name>:<port>"]`添加到将使用该注册表的图像的每个 Docker 引擎的`/etc/docker/daemon.json`中。

+   注意：出于许多安全原因，不建议使用此配置。

+   如果您使用无效的 HTTPS 证书，您还必须在所有客户端上将其标记为不安全的注册表。

+   这种配置也不建议，因为它只比不安全的注册表稍微好一点，可能会导致传输降级**中间人攻击（MITM）**。

我要给你的最后一条建议是，根据我的经验，注册表的云提供商后端文档一直都是错误的，并且一直（我敢说是故意的吗？）错误。我强烈建议，如果注册表拒绝了你的设置，你应该查看源代码，因为设置正确的变量相当不直观。你也可以使用挂载文件来配置注册表，但如果你不想在集群刚启动时构建一个新的镜像，环境变量是一个不错的选择。环境变量都是全大写的名称，用`_`连接起来，并与可用选项的层次结构相匹配：

```
parent
└─ child_option
 └─ some_setting
```

然后，注册表的这个字段将设置为`-e PARENT_CHILD_OPTION_SOME_SETTING=<value>`。

有关可用注册表选项的完整列表，您可以访问[`github.com/docker/docker-registry/blob/master/config/config_sample.yml`](https://github.com/docker/docker-registry/blob/master/config/config_sample.yml)，并查看您需要运行注册表的选项。正如前面提到的，我发现[docs.docker.com](https://docs.docker.com/)上的主要文档以及代码存储库本身的大部分文档在配置方面极不可靠，因此不要害怕阅读源代码以找出注册表实际期望的内容。

为了帮助那些将使用最有可能的后备存储（在“文件系统”之外）部署注册表的人，即`s3`，我将留下一个可用的（在撰写本文时）配置：

```
$ docker run -d \
 -p 5000:5000 \
 -v $(pwd)/registry_storage:/var/lib/registry \
             -e REGISTRY_STORAGE=s3 \
 -e REGISTRY_STORAGE_CACHE_BLOBDESCRIPTOR=inmemory \
 -e REGISTRY_STORAGE_S3_ACCESSKEY=<aws_key_id> \
 -e REGISTRY_STORAGE_S3_BUCKET=<bucket> \
 -e REGISTRY_STORAGE_S3_REGION=<s3_region> \
 -e REGISTRY_STORAGE_S3_SECRETKEY=<aws_key_secret> \
 --restart=always \
 --name registry \
 registry:2
```

```
 --name registry
```

# 底层存储驱动程序

这一部分对一些读者来说可能有点高级，并且并不严格要求阅读，但为了充分理解 Docker 如何处理镜像以及在大规模部署中可能遇到的问题，我鼓励每个人至少浏览一下，因为识别后备存储驱动程序问题可能会有用。另外，请注意，这里提到的问题可能随着 Docker 代码库的演变而变得不太适用，因此请查看他们的网站以获取最新信息。

与您可能从 Docker 守护程序期望的不同，本地图像层的处理实际上是以非常模块化的方式进行的，因此几乎可以将任何分层文件系统驱动程序插入到守护程序中。存储驱动程序控制着图像在您的 Docker 主机上的存储和检索方式，虽然从客户端的角度看可能没有任何区别，但每个驱动程序在许多方面都是独一无二的。

首先，我们将提到的所有可用存储驱动程序都是由 Docker 使用的底层容器化技术`containerd`提供的。虽然了解它之外的任何内容通常对大多数 Docker 用途来说都是多余的，但可以说它只是 Docker 用作图像处理 API 的底层模块之一。`containerd`提供了一个稳定的 API，用于存储和检索图像及其指定的层，以便构建在其之上的任何软件（如 Docker 和 Kubernetes）只需担心将其全部整合在一起。

您可能会在代码和/或文档中看到有关称为图形驱动程序的内容，这在学究式上是与存储驱动程序进行交互的高级 API，但在大多数情况下，当它被写入时，它用于描述实现图形驱动程序 API 的存储驱动程序；例如，当谈论新类型的存储驱动程序时，您经常会看到它被称为新的图形驱动程序。

要查看您正在使用的后备文件系统，可以输入`docker info`并查找`Storage Driver`部分：

```
$ docker info
<snip>
Storage Driver: overlay2
 Backing Filesystem: extfs
 Supports d_type: true
 Native Overlay Diff: true
<snip>
```

警告！在大多数情况下，更改存储驱动程序将删除您的计算机上由旧驱动程序存储的任何和所有图像和层的访问权限，因此请谨慎操作！此外，我相信通过更改存储驱动程序而不通过 CLI 手动清理图像和容器，或者通过从`/var/lib/docker/`中删除内容，将使这些图像和容器悬空，因此请确保在考虑这些更改时清理一下。

如果您想将存储驱动程序更改为我们将在此处讨论的任何选项，您可以编辑（或创建缺失的）`/etc/docker/daemon.json`并在其中添加以下内容，之后应重新启动 docker 服务：

```
{
  "storage-driver": "driver_name"
}
```

如果`daemon.json`不起作用，您还可以尝试通过向`DOCKER_OPTS`添加`-s`标志并重新启动服务来更改`/etc/default/docker`：

```
DOCKER_OPTS="-s driver_name"
```

一般来说，Docker 正在从`/etc/default/docker`（取决于发行版的路径）过渡到`/etc/docker/daemon.json`作为其配置文件，因此，如果您在互联网或其他文档中看到引用了前者文件，请查看是否可以找到`daemon.json`的等效配置，因为我相信它将在将来的某个时候完全取代另一个（就像所有的书籍一样，可能是在这本书发布后的一周内）。

所以现在我们知道了存储驱动程序是什么，以及如何更改它们，我们可以在这里使用哪些选项呢？

# aufs

`aufs`（也称为`unionfs`）是 Docker 可用的最古老但可能也是最成熟和稳定的分层文件系统。这种存储驱动程序通常启动快速，并且在存储和内存开销方面非常高效。如果您的内核已构建支持此驱动程序，Docker 将默认使用它，但通常情况下，除了 Ubuntu 并且只有安装了`linux-image-extra-$(uname -r)`软件包的情况下，大多数发行版都不会将该驱动程序添加到其内核中，也不会提供该驱动程序，因此您的计算机很可能无法运行它。您可以下载内核源代码并重新编译以支持`aufs`，但通常情况下，这是一个维护的噩梦，如果它不容易获得，您可能会选择不同的存储驱动程序。您可以使用`grep aufs /proc/filesystems`来检查您的计算机是否启用并可用`aufs`内核模块。

请注意，`aufs`驱动程序只能用于`ext4`和`xfs`文件系统。

# btrfs / zfs

这些在概念上不太像驱动程序，而更像是您在`/var/lib/docker`下挂载的实际文件系统，每个都有其自己的一套优缺点。一般来说，它们都会对性能产生影响，与其他选项相比具有较高的内存开销，但可能为您提供更容易的管理工具和/或更高密度的存储。由于这些驱动程序目前的支持有限，我听说仍然存在许多影响它们的关键错误，所以我不建议在生产环境中使用它们，除非您有非常充分的理由这样做。如果系统在`/var/lib/docker`下挂载了适当的驱动，并且相关的内核模块可用，Docker 将在`aufs`之后选择这些驱动程序。

请注意，这里的优先顺序并不意味着这两个存储驱动程序比本节中提到的其他存储驱动程序更可取，而纯粹是如果驱动器已挂载到适当（且不常见）的文件系统位置，则 Docker 将假定这是用户想要的配置。

# overlay 和 overlay2

这些特定的存储驱动程序正在逐渐成为 Docker 安装的首选。它们与`aufs`非常相似，但实现速度更快，更简单。与`aufs`一样，`overlay`和`overlay2`都需要包含和加载内核叠加模块，一般来说应该在 3.18 及更高版本的内核上可用。此外，两者只能在`ext4`或`xfs`文件系统上运行。`overlay`和`overlay2`之间的区别在于较新版本在内核 4.0 中添加了减少`inode`使用的改进，而较旧版本在领域中有更长的使用记录。如果您有任何疑问，`overlay2`几乎在任何情况下都是一个非常可靠的选择。

如果您以前没有使用过 inode，请注意它们包含有关文件系统上每个单独文件的元数据，并且在创建文件系统时大多数情况下都是硬编码的最大计数。虽然这种硬编码的最大值对于大多数一般用途来说是可以的，但也有一些边缘情况，您可能会用尽它们，这种情况下文件系统将在任何新文件创建时给出错误，即使您有可用空间来存储文件。如果您想了解更多关于这些结构的信息，您可以访问[`www.linfo.org/inode.html`](http://www.linfo.org/inode.html)。`overlay`和`overlay2`支持的存储驱动程序由于其内部处理文件复制的方式而被认为会导致大量的 inode 使用。虽然`overlay2`被宣传为不会出现这些问题，但我个人在使用默认 inode 最大值构建大型 Docker 卷时多次遇到 inode 问题。如果您曾经使用这些驱动程序并注意到磁盘已满但设备上仍有空间，请使用`df -i`检查 inode 是否已用尽，以确保不是 Docker 存储引起的问题。

# devicemapper

这个驱动程序不是在文件级设备上工作，而是直接在 Docker 实例所在的块设备上操作。虽然默认设置通常会设置一个回环设备，并且在本地测试时大多数情况下都很好，但由于在回环设备中创建的稀疏文件，这种特定设置极不建议用于生产系统。对于生产系统，建议您将其与`direct-lvm`结合使用，但这种复杂的设置需要特别棘手且比`overlay`存储驱动慢，因此我通常不建议使用它，除非您无法使用`aufs`或`overlay`/`overlay2`。

# Docker 存储的清理

如果您使用 Docker 镜像和容器，您会注意到，一般来说，Docker 会相对快速地消耗您提供的任何存储空间，因此建议定期进行适当的维护，以确保您的主机上不会积累无用的垃圾或者某些存储驱动程序的 inode 用尽。

# 手动清理

首先是清理您运行过但忘记使用`--rm`的所有容器，使用`docker rm`：

```
$ docker rm $(docker ps -aq)
86604ed7bb17
<snip>
7f7178567aba
```

这个命令有效地找到所有容器（`docker ps`），甚至是您停止的容器（`-a`标志），并且只返回它们的 ID（`-q`标志）。然后将其传递给`docker rm`，它将尝试逐个删除它们。如果有任何容器仍在运行，它将给出警告并跳过它们。一般来说，如果您的容器是无状态的或者具有在容器本身之外存储的状态，这通常是一个很好的做法，您可以随时执行。

接下来，尽管可能更具破坏性和节省空间，但要删除您积累的 Docker 镜像。如果您经常遇到空间问题，手动删除可能非常有效。一个经验法则是，任何标签为`<none>`的镜像（也称为悬空）通常可以使用`docker rmi`来删除，因为在大多数情况下，这些镜像表明该镜像已被`Dockerfile`的新版本取代：

```
$ docker images --filter "dangling=true"
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
<none>              <none>              873473f192c8        7 days ago          129MB
<snip>
registry            <none>              751f286bc25e        7 weeks ago         33.2MB

$ # Use those image IDs and delete them
$ docker rmi $(docker images -q --filter "dangling=true")
 Deleted: sha256:873473f192c8977716fcf658c1fe0df0429d4faf9c833b7c24ef269cacd140ff
<snip>
Deleted: sha256:2aee30e0a82b1a6b6b36b93800633da378832d623e215be8b4140e8705c4101f
```

# 自动清理

我们刚刚做的所有事情似乎都很痛苦，很难记住，所以 Docker 最近添加了`docker image prune`来帮助解决这个问题。通过使用`docker image prune`，所有悬空的镜像将被一条命令删除：

```
$ docker image prune 
WARNING! This will remove all dangling images.
Are you sure you want to continue? [y/N] y 
Deleted Images:
untagged: ubuntu@sha256:2b9285d3e340ae9d4297f83fed6a9563493945935fc787e98cc32a69f5687641
deleted: sha256:8b72bba4485f1004e8378bc6bc42775f8d4fb851c750c6c0329d3770b3a09086
<snip>
deleted: sha256:f4744c6e9f1f2c5e4cfa52bab35e67231a76ede42889ab12f7b04a908f058551

Total reclaimed space: 188MB
```

如果您打算清理与容器无关的所有镜像，还可以运行`docker image prune -a`。鉴于这个命令相当具有破坏性，除了在 Docker 从属节点上夜间/每周定时器上运行它以减少空间使用之外，在大多数情况下我不建议这样做。

需要注意的是，正如您可能已经注意到的，删除对镜像层的所有引用也会级联到子层。

最后但同样重要的是卷的清理，可以使用`docker volume`命令进行管理。我建议在执行此操作时要极度谨慎，以避免删除您可能需要的数据，并且只使用手动卷选择或`prune`。

```
$ docker volume ls
DRIVER              VOLUME NAME
local               database_volume
local               local_storage
local               swarm_test_database_volume

$ docker volume prune 
WARNING! This will remove all volumes not used by at least one container.
Are you sure you want to continue? [y/N] y 
Deleted Volumes:
local_storage
swarm_test_database_volume
database_volume

Total reclaimed space: 630.5MB
```

作为参考，我在写这一章的那周对 Docker 的使用相当轻，清理了陈旧的容器、镜像和卷后，我的文件系统使用量减少了大约 3GB。虽然这个数字大部分是个人经验，并且可能看起来不多，但在具有小实例硬盘的云节点和添加了持续集成的集群上，保留这些东西会比你意识到的更快地耗尽磁盘空间，因此期望花一些时间手动执行这个过程，或者为您的节点自动化这个过程，比如使用`systemd`定时器或`crontab`。

# 持久存储

既然我们已经讨论了瞬态本地存储，现在我们可以考虑当容器死亡或移动时，我们还有哪些选项可以保护数据安全。正如我们之前讨论过的，如果不能以某种方式将容器中的数据保存到外部源，那么当节点或容器在提供服务时意外死机时（比如您的数据库），您很可能会丢失其中包含的一些或全部数据，这绝对是我们想要避免的。使用一些形式的容器外部存储来存储您的数据，就像我们在之前的章节中使用挂载卷一样，我们可以开始使集群真正具有弹性，并且在其上运行的容器是无状态的。

通过使容器无状态，您可以放心地不用太担心容器在哪个 Docker 引擎上运行，只要它们可以拉取正确的镜像并使用正确的参数运行即可。如果您仔细考虑一下，您甚至可能会注意到这种方法与线程有很多相似之处，但是更加强大。您可以将 Docker 引擎想象成虚拟 CPU 核心，每个服务作为一个进程，每个任务作为一个线程。考虑到这一点，如果您的系统中的一切都是无状态的，那么您的集群也是无状态的，因此，您必须利用容器外的某种形式的数据存储来保护您的数据。

注意！最近，我注意到一些在线来源一直在建议您通过大规模复制服务、分片和集群化后端数据库来保留数据，而不将数据持久化在磁盘上，依赖于云提供商的分布式可用区和信任**服务级别协议**（SLA）来为您的集群提供弹性和自愈特性。虽然我同意这些集群在某种程度上是有弹性的，但如果没有某种形式的永久物理表示您的数据的存储，您可能会在数据完全复制之前遇到集群的级联故障，并且有风险丢失数据而无法恢复。在这里，我个人建议至少有一个节点在您的有状态服务中使用存储，这种存储是在出现问题时不会被擦除的物理介质（例如 NAS、AWS EBS 存储等）。

# 节点本地存储

这种存储类型是外部于容器的，专门用于将数据与容器实例分开，但仅限于在部署到同一节点的容器内使用。这种存储允许无状态容器设置，并具有许多面向开发的用途，例如隔离构建和读取配置文件，但对于集群部署来说，它受到严重限制，因为在其他节点上运行的容器将无法访问在原始节点上创建的数据。无论哪种情况，我们将在这里涵盖所有这些节点本地存储类型，因为大多数大型集群都使用节点本地存储和可重定位存储的某种组合。

# 绑定挂载

我们之前见过这些，但也许我们不知道它们是什么。绑定挂载将特定文件或文件夹挂载到容器沙箱中的指定位置，用`:`分隔。到目前为止，我们使用的一般语法应该类似于以下内容：

```
$ docker run <run_params> \
             -v /path/on/host:/path/on/container \
             <image>...
```

这个功能的新的 Docker 语法正在逐渐成为标准，其中`-v`和`--volume`现在正在被`--mount`替换，所以你也应该习惯这种语法。事实上，从现在开始，我们将尽可能多地使用两种语法，以便你能够熟悉任何一种风格，但在撰写本书时，`--mount`还没有像替代方案那样完全功能，所以根据工作情况和不工作情况，可能会有一些交替。

特别是在这里，在这个时候，一个简单的绑定挂载卷，带有绝对路径源，与几乎所有我们迄今为止使用的`--mount`样式都不起作用，这就是为什么我们之前没有介绍这种形式的原因。

说了这么多，不像`--volume`，`--mount`是一个`<key>=<value>`逗号分隔的参数列表：

+   `类型`：挂载的类型，可以是`bind`，`volume`或`tmpfs`。

+   `源`：挂载的源。

+   `target`：容器中源将被挂载的位置。

+   `readonly`：使挂载为只读。

+   `volume-opt`：卷的额外选项。可以输入多次。

这是我们用于`--volume`的比较版本：

```
$ docker run <run_params> \
             --mount source=/path/on/host,target=/path/on/container \
             <image>...
```

# 只读绑定挂载

我们之前没有真正涵盖的另一种绑定挂载类型是只读绑定挂载。当容器中挂载的数据需要保持只读时，这种配置非常有用，尤其是从主机向多个容器传递配置文件时。这种挂载卷的形式看起来有点像这样，适用于两种语法风格：

```
$ # Old-style
$ docker run <run_params> \
             -v /path/on/host:/path/on/container:ro \
             <image>...

$ # New-style
$ docker run <run_params> \
             --mount source=/path/on/host,target=/path/on/container,readonly \
             <image>...
```

正如稍早提到的，只读卷相对于常规挂载可以为我们提供一些东西，这是从主机传递配置文件到容器的。这通常在 Docker 引擎主机有一些影响容器运行代码的配置时使用（即，用于存储或获取数据的路径前缀，我们正在运行的主机，机器从`/etc/resolv.conf`使用的 DNS 解析器等），因此在大型部署中广泛使用，并且经常会看到。

作为一个很好的经验法则，除非你明确需要向卷写入数据，否则始终将其挂载为只读到容器中。这将防止从一个受损的容器传播到其他容器和主机本身的安全漏洞的意外打开。

# 命名卷

另一种卷挂载的形式是使用命名卷。与绑定挂载不同，命名数据卷（通常称为数据卷容器）提供了一种更便携的方式来引用卷，因为它们不依赖于对主机的任何了解。在底层，它们的工作方式几乎与绑定挂载完全相同，但由于使用更简单，它们更容易处理。此外，它们还有一个额外的好处，就是可以很容易地在容器之间共享，甚至可以由与主机无关的解决方案或完全独立的后端进行管理。

注意！如果命名的数据卷是通过简单地运行容器创建的，与字面上替换容器在挂载路径上的所有内容的绑定挂载不同，当容器启动时，命名的数据卷将把容器镜像在该位置的内容复制到命名的数据卷中。这种差异非常微妙，但可能会导致严重的问题，因为如果你忘记了这个细节或者假设它的行为与绑定挂载相同，你可能会在卷中得到意外的内容。

现在我们知道了命名数据卷是什么，让我们通过使用早期配置方法（而不是直接运行容器创建一个）来创建一个。

```
$ # Create our volume
$ docker volume create mongodb_data
mongodb_data

$ docker volume inspect mongodb_data
[
 {
 "Driver": "local",
 "Labels": {},
 "Mountpoint": "/var/lib/docker/volumes/mongodb_data/_data",
 "Name": "mongodb_data",
 "Options": {},
 "Scope": "local"
 }
]

$ # We can start our container now
$ # XXX: For non-bind-mounts, the new "--mount" option
$ #      works fine so we will use it here
$ docker run -d \
             --mount source=mongodb_data,target=/data/db \
             mongo:latest
888a8402d809174d25ac14ba77445c17ab5ed371483c1f38c918a22f3478f25a

$ # Did it work?
$ docker exec -it 888a8402 ls -la /data/db
total 200
drwxr-xr-x 4 mongodb mongodb  4096 Sep 16 14:10 .
drwxr-xr-x 4 root    root     4096 Sep 13 21:18 ..
-rw-r--r-- 1 mongodb mongodb    49 Sep 16 14:08 WiredTiger
<snip>
-rw-r--r-- 1 mongodb mongodb    95 Sep 16 14:08 storage.bson

$ # Stop the container
$ docker stop 888a8402 && docker rm 888a8402
888a8402
888a8402

$ # What does our host's FS have in the
$ # volume storage? (path used is from docker inspect output)
$ sudo ls -la /var/lib/docker/volumes/mongodb_data/_data
total 72
drwxr-xr-x 4  999 docker 4096 Sep 16 09:08 .
drwxr-xr-x 3 root root   4096 Sep 16 09:03 ..
-rw-r--r-- 1  999 docker 4096 Sep 16 09:08 collection-0-6180071043564974707.wt
<snip>
-rw-r--r-- 1  999 docker 4096 Sep 16 09:08 WiredTiger.wt

$ # Remove the new volume
$ docker volume rm mongodb_data
mongodb_data
```

在使用之前手动创建卷（使用`docker volume create`）通常是不必要的，但在这里这样做是为了演示这样做的长格式，但我们可以只是启动我们的容器作为第一步，Docker 将自行创建卷。

```
$ # Verify that we don't have any volumes
$ docker volume ls
DRIVER              VOLUME NAME

$ # Run our MongoDB without creating the volume beforehand
$ docker run -d \
             --mount source=mongodb_data,target=/data/db \
             mongo:latest
f73a90585d972407fc21eb841d657e5795d45adc22d7ad27a75f7d5b0bf86f69

$ # Stop and remove our container
$ docker stop f73a9058 && docker rm f73a9058
f73a9058
f73a9058

$ # Check our volumes
$ docker volume ls
DRIVER              VOLUME NAME
local               4182af67f0d2445e8e2289a4c427d0725335b732522989087579677cf937eb53
local               mongodb_data

$ # Remove our new volumes
$ docker volume rm mongodb_data 4182af67f0d2445e8e2289a4c427d0725335b732522989087579677cf937eb53
mongodb_data
4182af67f0d2445e8e2289a4c427d0725335b732522989087579677cf937eb53
```

你可能已经注意到，在这里，我们最终得到了两个卷，而不仅仅是我们预期的`mongodb_data`，如果你按照前面的例子进行了这个例子，你可能实际上有三个（一个命名，两个随机命名）。这是因为每个启动的容器都会创建`Dockerfile`中定义的所有本地卷，无论你是否给它们命名，而且我们的 MongoDB 镜像实际上定义了两个卷：

```
$ # See what volumes Mongo image defines
$ docker inspect mongo:latest | grep -A 3 Volumes
<snip>
            "Volumes": {
                "/data/configdb": {},
                "/data/db": {}
            },
```

我们只给第一个命名，所以`/data/configdb`卷收到了一个随机的名称。要注意这样的事情，因为如果你不够注意，你可能会遇到空间耗尽的问题。偶尔运行`docker volume prune`可以帮助回收空间，但要小心使用这个命令，因为它会销毁所有未绑定到容器的卷。

# 可移动卷

我们之前讨论的所有这些选项在单个主机上工作时都很好，但它们缺乏不同物理主机之间的真正数据可移植性。例如，当前的保持数据持久性的方法实际上可以扩展到但不能超出（没有一些极端的黑客行为）单个物理服务器与单个 Docker 引擎和共享附加存储。这对于强大的服务器可能还可以，但在真正的集群配置中开始缺乏任何形式的用途，因为您可能会处理未知数量的服务器，混合虚拟和物理主机，不同的地理区域等等。

此外，当容器重新启动时，您很可能无法轻易预测它将在何处启动，以便在其启动时为其提供卷后端。对于这种用例，有一些被称为可移动卷的东西。它们有各种不同的名称，比如“共享多主机存储”，“编排数据卷”等等，但基本上想法在各方面都是相同的：拥有一个数据卷，无论容器去哪里，它都会跟随。

为了举例说明，在这里，我们有三个主机，连接着两个有状态服务，它们都使用相同的可移动卷存储驱动程序：

+   **带有** **卷 D** 的**有状态容器 1**在**主机 1**上

+   **带有** **卷 G** 的**有状态容器 2**在**主机 3**上

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/93a9f826-7fc4-4a70-8c6b-6e60a163e9c1.png)

为了这个例子，假设**主机 3**已经死机。在正常的卷驱动程序情况下，**有状态** **容器 2**的所有数据都会丢失，但因为您将使用可移动存储：

+   编排平台将通知您的存储驱动程序容器已经死亡。

+   编排平台将指示它希望在具有可用资源的主机上重新启动被杀死的服务。

+   卷驱动程序将将相同的卷挂载到将运行服务的新主机上。

+   编排平台将启动服务，并将卷详细信息传递到新容器中。

在我们的假设示例中，新系统状态应该看起来有点像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/a4f48824-a92d-4373-ba82-6cbcf6c55d0a.png)

从外部观点来看，没有任何变化，数据无缝地过渡到新容器并保持其状态，这正是我们想要的。对于这个特定目的，有许多 Docker 卷驱动程序可供选择，每个驱动程序都有其自己的配置方法用于各种存储后端，但 Docker 预构建的 Azure 和 AWS 镜像中唯一包含的是 CloudStor，它仅适用于 Docker Swarm，使其非常特定且完全不可移植。

出于各种原因，包括技术的老化和 Docker 以及插件开发人员的支持不力，不得不进行这种类型的卷处理很可能会是在构建基础设施时您要花费大量时间的部分。我不想打击你的积极性，但在撰写本文时，无论易于教程可能让您相信的是，事实情况确实非常严峻。

您可以在[`docs.docker.com/engine/extend/legacy_plugins/#volume-plugins`](https://docs.docker.com/engine/extend/legacy_plugins/#volume-plugins)找到大多数驱动程序。配置后，如果您手动进行管理挂载而没有编排，可以按以下方式使用它们：

```
$ # New-style volume switch (--mount)
$ docker run --mount source=<volume_name>,target=/dest/path,volume-driver=<name> \
             <image>...

$ # Old-style volume switch
$ docker run -v <volume_name>:/dest/path \
             --volume-driver <name> \
             <image>...
```

供参考，目前我认为处理可移动卷最受欢迎的插件是 Flocker、REX-Ray ([`github.com/codedellemc/rexray`](https://github.com/codedellemc/rexray))和 GlusterFS，尽管有许多可供选择的插件，其中许多具有类似的功能。如前所述，对于如此重要的功能，这个生态系统的状态相当糟糕，似乎几乎每个大型参与者都在运行他们的集群时要么分叉并构建自己的存储解决方案，要么他们自己制作并保持封闭源。一些部署甚至选择使用标签来避免完全避开这个话题，并强制特定容器去特定主机，以便它们可以使用本地挂载的卷。

Flocker 的母公司 ClusterHQ 因财务原因于 2016 年 12 月停止运营，虽然缺乏支持会给不予提及提供一点推动力，但在撰写本书时，它仍然是最受欢迎的一种卷管理方式。所有代码都在 GitHub 上开源[`github.com/ClusterHQ`](https://github.com/ClusterHQ)，因此即使没有官方支持，你也可以构建、安装和运行它。如果你想在企业环境中使用这个插件，并希望得到支持，一些原始开发人员可以通过一个名为 ScatterHQ 的新公司进行雇佣[`www.scatterhq.com/`](https://www.scatterhq.com/)，他们在[`github.com/ScatterHQ`](https://github.com/ScatterHQ)上有自己的源代码库。GlusterFS 在其原始源中没有维护，就像 Flocker 一样，但你可以从源代码库[`github.com/calavera/docker-volume-glusterfs`](https://github.com/calavera/docker-volume-glusterfs)中构建、安装和运行完整的代码。如果你想要已经接收更新的代码版本，你可以在分支网络中找到一些[`github.com/calavera/docker-volume-glusterfs/network`](https://github.com/calavera/docker-volume-glusterfs/network)。

除了所有这些生态系统的分裂，这种与 Docker 集成的特定方式开始被弃用，而更倾向于管理和安装这些插件的“docker 插件”系统，这些插件是从 Docker Hub 作为 Docker 镜像安装的，但由于这些新风格插件的可用性不足，根据你的具体用例，你可能需要使用遗留插件。

很遗憾，在撰写本书时，“docker 插件”系统像许多其他功能一样是全新的，几乎没有可用的插件。例如，在早期提到的遗留插件中，唯一使用这个新系统构建的插件是 REX-Ray，但最流行的存储后端（EBS）插件似乎无法干净地安装。当你阅读本书时，这里的情况可能已经改变，但请注意，在你自己的实现中，你可能会使用经过验证的遗留插件。

因此，在提到所有这些警告之后，让我们实际尝试获取唯一一个可以使用新的“docker 插件安装”系统找到的插件（sshfs）：

要复制这项工作，您需要访问一个启用了 SSH 并且可以从 Docker 引擎运行的地方到达的辅助机器（尽管您也可以在回环上运行），因为它使用的是支持存储系统。您还需要在设备上创建目标文件夹`ssh_movable_volume`，可能还需要根据您的设置在`sshfs`卷参数中添加`-o odmap=user`。

```
$ # Install the plugin
$ docker plugin install vieux/sshfs 
Plugin "vieux/sshfs" is requesting the following privileges:
 - network: [host]
 - mount: [/var/lib/docker/plugins/]
 - mount: []
 - device: [/dev/fuse]
 - capabilities: [CAP_SYS_ADMIN]
Do you grant the above permissions? [y/N] y
latest: Pulling from vieux/sshfs
2381f72027fc: Download complete 
Digest: sha256:72c8cfd1a6eb02e6db4928e27705f9b141a2a0d7f4257f069ce8bd813784b558
Status: Downloaded newer image for vieux/sshfs:latest
Installed plugin vieux/sshfs

$ # Sanity check
$ docker plugin ls
ID                  NAME                 DESCRIPTION               ENABLED
0d160591d86f        vieux/sshfs:latest   sshFS plugin for Docker   true

$ # Add our password to a file
$ echo -n '<password>' > password_file

$ # Create a volume backed by sshfs on a remote server with SSH daemon running
$ docker volume create -d vieux/sshfs \
 -o sshcmd=user@192.168.56.101/ssh_movable_volume \
 -o password=$(cat password_file) \
 ssh_movable_volume
ssh_movable_volume

$ # Sanity check
$ docker volume ls
DRIVER               VOLUME NAME
vieux/sshfs:latest   ssh_movable_volume

$ # Time to test it with a container
$ docker run -it \
 --rm \
 --mount source=ssh_movable_volume,target=/my_volume,volume-driver=vieux/sshfs:latest \
 ubuntu:latest \
 /bin/bash

root@75f4d1d2ab8d:/# # Create a dummy file
root@75f4d1d2ab8d:/# echo 'test_content' > /my_volume/test_file

root@75f4d1d2ab8d:/# exit
exit

$ # See that the file is hosted on the remote server
$ ssh user@192.168.56.101
user@192.168.56.101's password: 
<snip>
user@ubuntu:~$ cat ssh_movable_volume/test_file 
test_content

$ # Get back to our Docker Engine host
user@ubuntu:~$ exit
logout
Connection to 192.168.56.101 closed.

$ # Clean up the volume
$ docker volume rm ssh_movable_volume
ssh_movable_volume
```

由于卷的使用方式，这个卷大多是可移动的，并且可以允许我们需要的可移动特性，尽管大多数其他插件使用一个在 Docker 之外并行在每个主机上运行的进程来管理卷的挂载、卸载和移动，因此这些指令将大不相同。

# 可移动卷同步丢失

在这一部分中还必须提到的最后一件事是，大多数处理卷移动的插件通常只能处理连接到单个节点，因为卷被多个源写入通常会导致严重问题，因此大多数驱动程序不允许这样做。

然而，这与大多数编排引擎的主要特性相冲突，即对 Docker 服务的更改将使原始服务保持运行，直到新服务启动并通过健康检查，从而需要在旧服务和新服务任务上挂载相同的卷，实际上产生了一个鸡蛋-鸡的悖论。

在大多数情况下，这可以通过确保 Docker 在启动新服务之前完全终止旧服务来解决，但即使这样，您也可以预期偶尔旧卷将无法从旧节点快速卸载，因此新服务将无法启动。

# 卷的 UID/GID 和安全考虑

这一部分不像我在其他地方放置的小信息框那样，因为这是一个足够大的问题，足够棘手，值得有自己的部分。要理解容器**用户 ID**（**UID**）和**组 ID**（**GID**）发生了什么，我们需要了解主机系统权限是如何工作的。当你有一个带有组和用户权限的文件时，它们实际上都被映射为数字，而不是保留为用户名或组名，当你使用常规的`ls`开关列出东西时，你会看到它们：

```
$ # Create a folder and a file that we will mount in the container
$ mkdir /tmp/foo
$ cd /tmp/foo
$ touch foofile

$ # Let's see what we have. Take note of owner and group of the file and directory
$ ls -la
total 0
drwxrwxr-x  2 user user   60 Sep  8 20:20 .
drwxrwxrwt 56 root root 1200 Sep  8 20:20 ..
-rw-rw-r--  1 user user    0 Sep  8 20:20 foofile

$ # See what our current UID and GID are
$ id
uid=1001(user) gid=1001(user) <snip>

$ # How about we see the actual values that the underlying system uses
$  ls -na
total 0
drwxrwxr-x  2 1001 1001   60 Sep  8 20:20 .
drwxrwxrwt 56    0    0 1200 Sep  8 20:20 ..
-rw-rw-r--  1 1001 1001    0 Sep  8 20:20 foofile
```

当您执行`ls`时，系统会读取`/etc/passwd`和`/etc/group`以显示权限的实际用户名和组名，这是 UID/GID 映射到权限的唯一方式，但底层值是 UID 和 GID。

正如你可能已经猜到的那样，这种用户到 UID 和组到 GID 的映射在容器化系统中可能无法很好地转换，因为容器将不具有相同的`/etc/passwd`和`/etc/group`文件，但外部卷上的文件权限是与数据一起存储的。例如，如果容器有一个 GID 为`1001`的组，它将匹配我们的`foofile`上的组权限位`-rw`，如果它有一个 UID 为`1001`的用户，它将匹配我们文件上的`-rw`用户权限。相反，如果您的 UID 和 GID 不匹配，即使容器和主机上有相同名称的组或用户，您也不会拥有正确的 UID 和 GID 以进行适当的权限处理。是时候看看我们可以用这个做成什么样的混乱了：

```
$ ls -la
total 0
drwxrwxr-x  2 user user   60 Sep  8 21:16 .
drwxrwxrwt 57 root root 1220 Sep  8 21:16 ..
-rw-rw-r--  1 user user    0 Sep  8 21:16 foofile 
$ ls -na
total 0
drwxrwxr-x  2 1001 1001   60 Sep  8 21:16 .
drwxrwxrwt 57    0    0 1220 Sep  8 21:16 ..
-rw-rw-r--  1 1001 1001    0 Sep  8 21:16 foofile

$ # Start a container with this volume mounted
$ # Note: We have to use the -v form since at the time of writing this
$ #       you can't mount a bind mount with absolute path :(
$ docker run --rm \
             -it \
             -v $(pwd)/foofile:/tmp/foofile \
             ubuntu:latest /bin/bash

root@d7776ec7b655:/# # What does the container sees as owner/group?
root@d7776ec7b655:/# ls -la /tmp
total 8
drwxrwxrwt 1 root root 4096 Sep  9 02:17 .
drwxr-xr-x 1 root root 4096 Sep  9 02:17 ..
-rw-rw-r-- 1 1001 1001    0 Sep  9 02:16 foofile 
root@d7776ec7b655:/# # Our container doesn't know about our users
root@d7776ec7b655:/# # so it only shows UID/GID 
root@d7776ec7b655:/# # Let's change the owner/group to root (UID 0) and set setuid flag
root@d7776ec7b655:/# chown 0:0 /tmp/foofile 
root@d7776ec7b655:/# chmod +x 4777 /tmp/foofile 

root@d7776ec7b655:/# # See what the permissions look like now in container
root@d7776ec7b655:/# ls -la /tmp
total 8
drwxrwxrwt 1 root root 4096 Sep  9 02:17 .
drwxr-xr-x 1 root root 4096 Sep  9 02:17 ..
-rwsrwxrwx 1 root root    0 Sep  9 02:16 foofile

root@d7776ec7b655:/# # Exit the container
root@d7776ec7b655:/# exit
exit

$ # What does our unmounted volume looks like?
$ ls -la
total 0
drwxrwxr-x  2 user user   60 Sep  8 21:16 .
drwxrwxrwt 57 root root 1220 Sep  8 21:17 ..
-rwsrwxrwx  1 root root    0 Sep  8 21:16 foofile
$ # Our host now has a setuid file! Bad news! 
```

警告！在文件上设置`setuid`标志是一个真正的安全漏洞，它以文件所有者的权限执行文件。如果我们决定编译一个程序并在其上设置此标志，我们可能会对主机造成大量的破坏。有关此标志的更多信息，请参阅[`en.wikipedia.org/wiki/Setuid`](https://en.wikipedia.org/wiki/Setuid)。

正如你所看到的，如果我们决定更加恶意地使用我们的`setuid`标志，这可能是一个严重的问题。这个问题也延伸到我们使用的任何挂载卷，因此在处理它们时，请确保您要谨慎行事。

Docker 一直在努力使用户命名空间工作，以避免一些这些安全问题，它通过`/etc/subuid`和`/etc/subgid`文件重新映射 UID 和 GID 到容器内的其他内容，以便在主机和容器之间没有`root` UID 冲突，但它们并不是没有问题的（在撰写本书时存在大量问题）。有关使用用户命名空间的更多信息，您可以在[`docs.docker.com/engine/security/userns-remap/`](https://docs.docker.com/engine/security/userns-remap/)找到更多信息。

加剧这个 UID/GID 问题的是另一个问题，即在这样的独立环境中会发生的问题：即使在两个容器之间以相同的顺序安装了所有相同的软件包，由于用户和组通常是按名称而不是特定的 UID/GID 创建的，你不能保证在容器运行之间这些一致，如果你想重新挂载已升级或重建的容器之间的相同卷，这是一个严重的问题。因此，你必须确保卷上的 UID 和 GID 是稳定的，方法类似于我们在一些早期示例中所做的，在安装包之前：

```
RUN groupadd -r -g 910 mongodb && \
 useradd -r -u 910 -g 910 mongodb && \
 mkdir -p /data/db && \
 chown -R mongodb:mongodb /data/db && \
 chmod -R 700 /data/db && \
 apt-get install mongodb-org
```

在这里，我们创建了一个 GID 为`910`的组`mongodb`和一个 UID 为`910`的用户`mongodb`，然后确保我们的数据目录由它拥有，然后再安装 MongoDB。通过这样做，当安装`mongodb-org`软件包时，用于运行数据库的组和用户已经存在，并且具有不会更改的确切 UID/GID。有了稳定的 UID/GID，我们可以在任何具有相同配置的构建容器上挂载和重新挂载卷，因为这两个数字将匹配，并且它应该在我们将卷移动到的任何机器上工作。

最后可能需要担心的一件事（在上一个示例中也是一个问题）是，挂载文件夹将覆盖主机上已创建的文件夹并替换其权限。这意味着，如果你将一个新文件夹挂载到容器上，要么你必须手动更改卷的权限，要么在容器启动时更改所有权。让我们看看我是什么意思：

```
$ mkdir /tmp/some_folder
$ ls -la /tmp | grep some_folder
drwxrwxr-x  2 sg   sg        40 Sep  8 21:56 some_folder

$ # Mount this folder to a container and list the content
$ docker run -it \
             --rm \
             -v /tmp/some_folder:/tmp/some_folder \
             ubuntu:latest \
             ls -la /tmp
total 8
drwxrwxrwt 1 root root 4096 Sep  9 02:59 .
drwxr-xr-x 1 root root 4096 Sep  9 02:59 ..
drwxrwxr-x 2 1000 1000   40 Sep  9 02:56 some_folder

$ # Somewhat expected but we will do this now by overlaying
$ # an existing folder (/var/log - root owned) in the container

$ # First a sanity chech
$ docker run -it \
             --rm \
             ubuntu:latest \
             ls -la /var | grep log
drwxr-xr-x 4 root root  4096 Jul 10 18:56 log 
$ # Seems ok but now we mount our folder here
$ docker run -it \
             --rm \
             -v /tmp/some_folder:/var/log \
             ubuntu:latest \
             ls -la /var | grep log
drwxrwxr-x 2 1000  1000   40 Sep  9 02:56 log
```

正如你所看到的，容器内文件夹上已经设置的任何权限都被我们挂载的目录卷完全覆盖了。如前所述，避免在容器中运行服务的有限用户出现权限错误的最佳方法是在容器启动时使用包装脚本更改挂载路径上的权限，或者使用挂载卷启动容器并手动更改权限，前者是更可取的选项。最简单的包装脚本大致如下：

```
#!/bin/bash -e

# Change owner of volume to the one we expect
chown mongodb:mongodb /path/to/volume

# Optionally you can use this recursive version too
# but in most cases it is a bit heavy-handed
# chown -R mongodb:mongodb /path/to/volume

su - <original limited user> -c '<original cmd invocation>'
```

将此脚本放在容器的`/usr/bin/wrapper.sh`中，并在`Dockerfile`中以 root 身份运行的地方添加以下代码片段应该足以解决问题：

```
<snip>
CMD [ "/usr/bin/wrapper.sh" ]
```

当容器启动时，卷将已经挂载，并且脚本将在将命令传递给容器的原始运行程序之前，更改卷的用户和组为正确的用户和组，从而解决了我们的问题。

从本节中最重要的收获应该是，在处理卷时，您应该注意用户权限，因为如果不小心，它们可能会导致可用性和安全性问题。当您开发您的服务和基础设施时，这些类型的陷阱可能会导致从轻微头痛到灾难性故障的一切，但是现在您对它们了解更多，我们希望已经预防了最坏的情况。

# 总结

在本章中，您已经学到了大量关于 Docker 数据处理的新知识，包括 Docker 镜像内部和运行自己的 Docker 注册表。我们还涵盖了瞬态、节点本地和可重定位数据存储以及相关的卷管理，这将帮助您有效地在云中部署您的服务。随后，我们花了一些时间来介绍卷编排生态系统，以帮助您在 Docker 卷驱动程序的不断变化中进行导航，因为在这个领域事情变化得很快。最后，我们还涵盖了各种陷阱（如 UID/GID 问题），以便您可以在自己的部署中避免它们。

在我们继续进入下一章时，我们将介绍集群加固以及如何以有序的方式在大量服务之间传递数据。 


# 第六章：高级部署主题

我们已经花了相当多的时间讨论容器通信和安全性，但在本章中，我们将进一步探讨以下内容：

+   高级调试技术。

+   实现队列消息传递。

+   运行安全检查。

+   深入容器安全。

我们还将介绍一些其他工具和技术，帮助您更好地管理部署。

# 高级调试

在野外调试容器的能力是一个非常重要的话题，我们之前介绍了一些基本的技术，可以在这里派上用场。但也有一些情况下，`docker ps`和`docker exec`并不够用，因此在本节中，我们将探讨一些可以添加到您的工具箱中的其他工具，可以帮助解决那些棘手的问题。

# 附加到容器的进程空间

有时容器正在运行的是极简的发行版，比如 Alpine Linux（[`www.alpinelinux.org/`](https://www.alpinelinux.org/)），而且容器本身存在一个你想要调试的进程问题，但缺乏基本的调试工具。默认情况下，Docker 会将所有容器隔离在它们各自的进程命名空间中，因此我们之前直接附加到容器并尝试使用非常有限的工具来找出问题的调试工作流在这里不会有太大帮助。

幸运的是，Docker 完全能够使用`docker run --pid "container:<name_or_id>"`标志加入两个容器的进程命名空间，这样我们就可以直接将调试工具容器附加到受影响的容器上：

```
$ # Start an NGINX container
$ docker run -d --rm nginx
650a1baedb0c274cf91c086a9e697b630b2b60d3c3f94231c43984bed1073349

$ # What can we see from a new/separate container?
$ docker run --rm \
 ubuntu \
 ps -ef 
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 16:37 ?        00:00:00 ps -ef

$ # Now let us try the same thing but attach to the NGINX's PID space
$ docker run --rm \
 --pid "container:650a1bae" \
 ubuntu \
 ps -ef 
UID      PID  PPID  C STIME TTY    TIME CMD
root       1     0  0 16:37 ?      00:00:00 nginx: master process nginx -g daemon off;
systemd+   7     1  0 16:37 ?      00:00:00 nginx: worker process
root       8     0  0 16:37 ?      00:00:00 ps -ef
```

正如你所看到的，我们可以将一个调试容器附加到相同的 PID 命名空间中，以这种方式调试任何行为异常的进程，并且可以保持原始容器不受调试工具的安装！使用这种技术，原始容器可以保持较小，因为工具可以单独安装，而且容器在整个调试过程中保持运行，因此您的任务不会被重新安排。也就是说，当您使用这种方法调试不同的容器时，要小心不要杀死其中的进程或线程，因为它们有可能会级联并杀死整个容器，从而停止您的调查。

有趣的是，这个`pid`标志也可以通过`--pid host`来调用，以共享主机的进程命名空间，如果你有一个在你的发行版上无法运行的工具，并且有一个 Docker 容器可以运行它（或者，如果你想要使用一个容器来管理主机的进程）：

```
$ # Sanity check
$ docker run --rm \
 ubuntu \
 ps -ef 
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 16:44 ?        00:00:00 ps -ef

$ # Now we try to attach to host's process namespace
$ docker run --rm \
 --pid host \
 ubuntu \
 ps -ef 
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 15:44 ?        00:00:02 /sbin/init splash
root         2     0  0 15:44 ?        00:00:00 [kthreadd]
root         4     2  0 15:44 ?        00:00:00 [kworker/0:0H]
<snip>
root      5504  5485  3 16:44 ?        00:00:00 ps -ef
```

很明显，这个标志的功能对于运行和调试应用程序提供了多少能力，所以不要犹豫使用它。

警告！与容器共享主机的进程命名空间是一个很大的安全漏洞，因为恶意容器可以轻易地通过操纵进程来控制或者 DoS 主机，特别是如果容器的用户是以 root 身份运行的。因此，在使用`--pid host`时要格外小心，并确保只在你完全信任的容器上使用这个标志。

# 调试 Docker 守护程序

如果到目前为止这些技术都没有帮助到你，你可以尝试运行 Docker 容器，并使用`docker system events`来检查守护程序 API 正在执行的操作，该命令可以跟踪几乎所有在其 API 端点上触发的操作。你可以用它来进行审计和调试，但一般来说，后者是它的主要目的，就像你在下面的例子中所看到的那样。

在第一个终端上运行以下命令，并让它保持运行，这样我们就可以看到我们可以收集到什么信息：

```
$ docker system events
```

在另一个终端上，我们将运行一个新的容器：

```
$ docker run -it \
 --rm \
 ubuntu /bin/bash 
$ root@563ad88c26c3:/# exit
exit
```

在你完成了对容器的启动和停止之后，第一个终端中的`events`命令应该输出类似于这样的内容：

```
$ docker system events
2017-09-27T10:54:58.943347229-07:00 container create 563ad88c26c3ae7c9f34dfe05c77376397b0f79ece3e233c0ce5e7ae1f01004f (image=ubuntu, name=thirsty_mccarthy)
2017-09-27T10:54:58.943965010-07:00 container attach 563ad88c26c3ae7c9f34dfe05c77376397b0f79ece3e233c0ce5e7ae1f01004f (image=ubuntu, name=thirsty_mccarthy)
2017-09-27T10:54:58.998179393-07:00 network connect 1e1fd43bd0845a13695ea02d77af2493a449dd9ee50f2f1372f589dc4968410e (container=563ad88c26c3ae7c9f34dfe05c77376397b0f79ece3e233c0ce5e7ae1f01004f, name=bridge, type=bridge)
2017-09-27T10:54:59.236311822-07:00 container start 563ad88c26c3ae7c9f34dfe05c77376397b0f79ece3e233c0ce5e7ae1f01004f (image=ubuntu, name=thirsty_mccarthy)
2017-09-27T10:54:59.237416694-07:00 container resize 563ad88c26c3ae7c9f34dfe05c77376397b0f79ece3e233c0ce5e7ae1f01004f (height=57, image=ubuntu, name=thirsty_mccarthy, width=176)
2017-09-27T10:55:05.992143308-07:00 container die 563ad88c26c3ae7c9f34dfe05c77376397b0f79ece3e233c0ce5e7ae1f01004f (exitCode=0, image=ubuntu, name=thirsty_mccarthy)
2017-09-27T10:55:06.172682910-07:00 network disconnect 1e1fd43bd0845a13695ea02d77af2493a449dd9ee50f2f1372f589dc4968410e (container=563ad88c26c3ae7c9f34dfe05c77376397b0f79ece3e233c0ce5e7ae1f01004f, name=bridge, type=bridge)
2017-09-27T10:55:06.295496139-07:00 container destroy 563ad88c26c3ae7c9f34dfe05c77376397b0f79ece3e233c0ce5e7ae1f01004f (image=ubuntu, name=thirsty_mccarthy)
```

它的使用范围相当有限，但是这种跟踪方式，以及我们到目前为止讨论过的其他技巧，应该为你提供在基于 Docker 的集群上解决几乎任何类型的问题的工具。除了已经提到的一切之外，在我的个人经验中，也有几次需要使用`gdb`，还有几次问题最终被证明是上游 bug。因此，在扩展规模时，要做好准备，因为出现新问题的可能性也会增加。

# 高级网络

网络是 Docker 集群中最重要的事情之一，它需要在整个系统的集群上保持运行顺畅，以便系统能够以任何能力运行。考虑到这一点，我们有理由涵盖一些我们尚未讨论但在大多数实际部署中都很重要的主题。您很有可能会在自己的部署中遇到至少其中一个用例，因此我建议您全文阅读，但您的情况可能有所不同。

# 静态主机配置

在某些特定的配置中，您可能有一个需要映射或重新映射到容器尝试到达的特定 IP 地址的网络主机。这允许对命名服务器进行灵活配置，并且对于网络上没有良好的网络 DNS 服务器的静态主机来说，这可能是一个真正的救命稻草。

要将这样的主机映射添加到容器中，您可以使用`docker run --add-host`命令运行容器，并使用此标志，将在`/etc/hosts`中添加一个与您的输入匹配的条目，以便您可以正确地将请求路由到它：

```
$ # Show what the default /etc/hosts has
$ docker run --rm \
 -it \
 ubuntu \
 /bin/cat /etc/hosts 
127.0.0.1    localhost
::1    localhost ip6-localhost ip6-loopback
fe00::0    ip6-localnet
ff00::0    ip6-mcastprefix
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
172.17.0.2    3c46adb8a875

$ # We now will add our fake server1 host mapping
$ docker run --rm \
 -it \
 --add-host "server1:123.45.67.89" \
 ubuntu \
 /bin/cat /etc/hosts 
127.0.0.1    localhost
::1    localhost ip6-localhost ip6-loopback
fe00::0    ip6-localnet
ff00::0    ip6-mcastprefix
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
123.45.67.89    server1
172.17.0.2    dd4d7c6ef7b8

$ # What does the container see when we have an additional host?
$ docker run --rm \
 -it \
 --add-host "server1:123.45.67.89" \
 ubuntu /bin/bash 
root@0ade7f3e8a80:/# getent hosts server1
123.45.67.89    server1

root@0ade7f3e8a80:/# exit
exit
```

如前所述，当您有一个非容器化服务时，您可能不希望将 IP 硬编码到容器中，该服务也无法从互联网 DNS 服务器解析时，这可能非常有用。

# DNS 配置

说到 DNS，我们可能应该稍微谈谈 Docker DNS 处理。默认情况下，Docker 引擎使用主机的 DNS 设置，但在一些高级部署设置中，集群所在的网络可能已经构建好，此时可能需要配置引擎或容器的自定义 DNS 设置或 DNS 搜索前缀（也称为域名）。在这种情况下，您可以通过向`/etc/docker/daemon.json`添加`dns`和/或`dns-search`参数并重新启动守护程序来轻松覆盖 Docker 引擎的默认 DNS 设置。这两个参数都允许多个值，并且相当容易理解。

```
{
...
        "dns": ["1.2.3.4", "5.6.7.8", ...],
        "dns-search": ["domain.com", ...],
...
}
```

在我曾经工作过的所有网络设置中，我从未见过覆盖 DNS 服务器 IP 或 DNS 搜索前缀是部署自己的 DHCP 服务器并设置适当的选项来设置 DNS 服务器（`选项 6`）和域名（`选项 15`）更好的选择，当初始化网络接口时，机器将会选择这些选项。如果您想了解更多关于这些 DHCP 标志的信息，我强烈建议您访问[`en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol#DHCP_options`](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol#DHCP_options)并在使用我们之前阅读相关内容。注意！在某些情况下，引擎主机的 DNS 服务器指向`localhost`范围，就像大多数`systemd-resolve`和`dnsmasq`设置一样，容器无法访问主机的`localhost`地址，因此默认情况下，所有在该实例上运行的容器都会被替换为 Google 的 DNS 服务器（`8.8.8.8`和`8.8.4.4`）。如果您想在容器中保留主机的 DNS 设置，您必须确保配置中的 DNS 解析器不是`localhost` IP 范围之一，并且可以被容器网络访问。您可以在[`docs.docker.com/engine/userguide/networking/default_network/configure-dns/`](https://docs.docker.com/engine/userguide/networking/default_network/configure-dns/)找到更多信息。

如果您对引擎范围的配置不感兴趣，只想覆盖单个容器的 DNS 设置，您可以通过向`docker run`命令添加`--dns`和`--dns-search`选项来执行等效操作，这将替换相关容器中的默认`/etc/resolv.conf`设置。

```
$ # Since my default DNS is pointed to localhost, the default should be Google's DNS servers
$ docker run --rm \
 -it \
 ubuntu \
 /bin/cat /etc/resolv.conf 
# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "systemd-resolve --status" to see details about the actual nameservers.
nameserver 8.8.8.8
nameserver 8.8.4.4

$ # Now we will specify a custom DNS and DNS search prefix and see what the same file looks like
$ docker run --rm \
 -it \
 --dns 4.4.4.2 \
 --dns-search "domain.com" \
 ubuntu \
 /bin/cat /etc/resolv.conf 
search domain.com
nameserver 4.4.4.2
```

正如您所看到的，容器中的设置已经更改以匹配我们的参数。在我们的情况下，任何 DNS 解析都将流向`4.4.4.2`服务器，并且任何未经验证的主机名将首先尝试解析为`<host>.domain.com`。

# 叠加网络

我们在《第四章》*扩展容器*中只是简单提及了这一点，但为了使我们的容器能够与 Swarm 服务发现一起工作，我们不得不创建这种类型的网络，尽管我们并没有花太多时间解释它是什么。在 Docker Swarm 的上下文中，一台机器上的容器无法访问另一台机器上的容器，因为它们的网络直接路由到下一个跳点，而桥接网络阻止了每个容器在同一节点上访问其邻居。为了在这种多主机设置中无缝地连接所有容器，您可以创建一个覆盖整个集群的 overlay 网络。遗憾的是，这种类型的网络只在 Docker Swarm 集群中可用，因此在编排工具中的可移植性有限，但您可以使用`docker network create -d overlay network_name`来创建一个。由于我们已经在《第四章》*扩展容器*中涵盖了使用这种类型网络的部署示例，您可以在那里查看它的运行情况。

注意！默认情况下，覆盖网络不会与其他节点安全地通信，因此在创建时使用`--opt encrypted`标志是非常鼓励的，特别是在网络传输不能完全信任的情况下。使用此选项将产生一些处理成本，并要求您在集群内允许端口`50`的通信，但在大多数情况下，打开它应该是值得的。

# Docker 内置网络映射

在之前的章节中，我们大多数情况下都是使用默认网络设置的容器，大多数情况下都是使用`bridge`网络，因为这是默认设置，但这并不是容器可以使用的唯一类型的网络。以下是可用网络连接的列表，几乎所有这些连接都可以通过`docker run --network`参数进行设置：

+   `bridge`：如前几章所述，这种类型的网络在主机上创建了一个独立的虚拟接口，用于与容器通信，容器可以与主机和互联网通信。通常情况下，这种类型的网络会阻止容器之间的通信。

+   `none`：禁用容器的所有网络通信。这对于只包含工具的容器并且不需要网络通信的情况非常有用。

+   `host`：使用主机的网络堆栈，不创建任何虚拟接口。

+   `<network_name_or_id>`：连接到命名网络。当您创建一个网络并希望将多个容器放入相同的网络组时，此标志非常有用。例如，这对于连接多个喋喋不休的容器（如 Elasticsearch）到它们自己的隔离网络中将非常有用。

+   `<container_name_or_id>`：这允许您连接到指定容器的网络堆栈。就像`--pid`标志一样，这对于调试运行中的容器非常有用，而无需直接附加到它们，尽管根据使用的网络驱动程序，网络可能需要使用`--attachable`标志进行创建。

警告！使用`host`网络开关会使容器完全访问本地系统服务，因此在除测试之外的任何情况下使用都是一种风险。在使用此标志时要非常小心，但幸运的是，只有极少数情况（如果有的话）会有正当使用这种模式的情况。

# Docker 通信端口

除非您正在运行 Docker Swarm，否则您可能永远不需要担心 Docker 用于通信的端口，但这是一个相对重要的参考点，如果您在现场遇到这样的配置或者您想在集群中部署这样的部署。列表非常简短，但每个端口对于大多数 Swarm 集群的操作非常重要：

```
2377 TCP - Used for Swarm node communication
4789 UDP - Container ingress network
7946 TCP/UDP - Container network discovery
50 IP - Used for secure communication of overlay networks if you use "--opt encrypted" when creating the overlay network
```

# 高可用性管道

以前，我们大部分时间都在集群中的节点之间进行基于套接字的通信，这通常是大多数人可以理解的事情，并且几乎每种编程语言都有围绕它构建的工具。因此，这是人们将经典基础架构转换为容器时通常会选择的第一个工具，但对于大规模及以上规模的纯数据处理，由于超出了处理管道其余阶段的容量而导致的背压，它根本不起作用。

如果您将每个集群服务想象为一系列连续的转换步骤，那么基于套接字的系统将经历类似于这些步骤的循环：

+   打开一个监听套接字。

+   永远循环执行以下操作：

+   在套接字上等待来自上一阶段的数据。

+   处理这些数据。

+   将处理后的数据发送到下一阶段的套接字。

但是，如果下一个阶段已经达到最大容量，最后一步会发生什么呢？大多数基于套接字的系统要么会抛出异常并完全失败处理管道的这一特定数据，要么阻止执行继续并不断重试将数据发送到下一个阶段直到成功。由于我们不希望处理管道失败，因为结果并非错误，也不希望让我们的工作人员等待下一个阶段解除阻塞，我们需要一些可以按顺序保存阶段输入的东西，以便前一个阶段可以继续处理自己的新输入。

# 容器消息

对于我们刚刚讨论的情景，即个别处理阶段的背压导致级联回流停止的情况，消息队列（通常也称为发布/订阅消息系统）在这里为我们提供了我们需要的确切解决方案。消息队列通常将数据存储为**先进先出**（FIFO）队列结构中的消息，并通过允许发送方将所需的输入添加到特定阶段的队列（"入队"），并允许工作人员（监听器）在该队列中触发新消息来工作。当工作人员处理消息时，队列会将其隐藏在其他工作人员之外，当工作人员完成并成功时，消息将永久从队列中删除。通过以异步方式处理结果，我们可以允许发送方继续处理自己的任务，并完全模块化数据处理管道。

为了看到队列的运作，假设我们有两个正在运行的容器，并且在很短的时间内，消息**A**、**B**、**C**和**D**一个接一个地作为来自某个想象的处理步骤的输入到达（红色表示队列顶部）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/4ca21d49-acf4-4270-9a8b-5ebe5a31716f.png)

在内部，队列跟踪它们的顺序，最初，容器队列监听器都没有注意到这些消息，但很快，它们收到通知，有新的工作要做，所以它们按接收顺序获取消息。消息队列（取决于确切的实现）将这些消息标记为不可用于其他监听器，并为工作人员设置一个完成的超时。在这个例子中，**消息 A**和**消息 B**已被标记为可供可用工作人员处理：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/8c7c07c9-7469-4ebd-9884-94731f6384d2.png)

在这个过程中，假设**容器**1 发生了灾难性故障并且它就这样死了。**消息 A**在队列中的超时时间到期，而它还没有完成，所以队列将其放回顶部，并使其再次可用于侦听器，而我们的另一个容器继续工作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/23561640-e0a7-44ad-8f4a-b5076d565155.png)

成功完成**消息 B**后，**容器 2**通知队列任务已完成，并且队列将其从列表中完全移除。完成这一步后，容器现在取出最顶部的消息，结果是未完成的**消息 A**，整个过程就像以前一样进行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/97d75585-51a9-4eef-bdf8-9bb82855def0.png)

在这个集群阶段处理故障和过载的同时，将所有这些消息放入队列的上一个阶段继续处理其专用工作负载。即使在某个随机时间点，我们的处理能力的一半被强制移除，我们当前的阶段也没有丢失任何数据。

现在，工作人员的新伪代码循环会更像这样：

+   在队列上注册为侦听器。

+   永远循环执行以下操作：

+   等待队列中的消息。

+   处理队列中的数据。

+   将处理后的数据发送到下一个队列。

有了这个新系统，如果管道中的某个阶段出现任何处理减速，那么这些过载阶段的队列将开始增长，但如果较早的阶段减速，队列将缩小直到为空。只要最大队列大小能够处理消息的数量，过载阶段能够处理平均需求，你就可以确定管道中的所有数据最终都会被处理，而且扩展阶段的触发器几乎就像是注意到不是由错误引起的更大的队列一样简单。这不仅有助于缓解管道阶段扩展的差异，而且还有助于在集群的某些部分出现故障时保留数据，因为队列在故障时会增长，然后在将基础设施恢复到正常工作时会清空 - 所有这些都将在不丢失数据的情况下发生。

如果这些好处的组合还不够积极，那么请考虑现在可以保证数据已经被处理，因为队列会保留数据，所以如果一个工作进程死掉，队列会（正如我们之前看到的）将消息放回队列，可能由另一个工作进程处理，而不像基于套接字的处理那样在这种情况下会悄然死去。处理密度的增加、故障容忍度的增加以及对突发数据的更好处理使队列对容器开发者非常有吸引力。如果你所有的通信也都是通过队列完成的，那么服务发现甚至可能不需要对这些工作进程进行除了告诉它们队列管理器在哪里之外的工作，因为队列正在为你做这项发现工作。

毫不奇怪，大多数队列都需要开发成本，这就是为什么它们没有像人们预期的那样被广泛使用的原因。在大多数情况下，你不仅需要将自定义队列客户端库添加到你的工作代码中，而且在许多类型的部署中，你还需要一个处理消息的主要队列仲裁者的进程或守护进程。事实上，我可能会说选择消息系统本身就是一个研究任务，但如果你正在寻找快速答案，一般来说，Apache Kafka（[`kafka.apache.org/`](https://kafka.apache.org/)）、RabbitMQ（[`www.rabbitmq.com/`](https://www.rabbitmq.com/)）和基于 Redis 的自定义实现（[`redis.io/`](https://redis.io/)）似乎在集群环境中更受欢迎，从最大的部署到最小的部署。

就像我们迄今为止一直在讨论的所有事物一样，大多数云提供商都提供了某种类型的服务（如 AWS SQS，Google Cloud Pub/Sub，Azure Queue Storage 等），这样你就不必自己构建它。如果你愿意多花一点钱，你可以利用这些服务，而不必担心自己托管守护进程。从历史上看，消息队列在内部维护和管理方面一直很难，所以我敢说，许多云系统使用这些服务，而不是部署自己的服务。

# 实现我们自己的消息队列

理论讲解完毕，让我们看看如何构建我们自己的小型队列发布者和监听者。在这个例子中，我们将使用基于 Redis 的较简单的消息系统之一，名为`bull`（[`www.npmjs.com/package/bull`](https://www.npmjs.com/package/bull)）。首先，我们将编写将运行整个系统的代码，并且为了简化操作，我们将同时使用相同的镜像作为消费者和生产者。

在一个新的目录中，创建以下内容：

作为提醒，这段代码也在 GitHub 存储库中，如果你不想输入完整的文本，可以在[`github.com/sgnn7/deploying_with_docker/tree/master/chapter_6/redis_queue`](https://github.com/sgnn7/deploying_with_docker/tree/master/chapter_6/redis_queue)查看或克隆它。

# package.json

这个文件基本上只是我们旧的示例的副本，增加了`bull`包和名称更改：

```
{
  "name": "queue-worker",
  "version": "0.0.1",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "bull": "³.2.0"
  }
}
```

# index.js

`index.js`是一个单文件应用程序，根据调用参数，每 1.5 秒要么向队列发送一个时间戳，要么从队列中读取。队列位置由`QUEUE_HOST`环境变量定义：

```
'use strict'

const Queue = require('bull');

const veryImportantThingsQueue = new Queue('very_important_things',
                                           { redis: { port: 6379,
                                                      host: process.env.QUEUE_HOST }});

// Prints any message data received
class Receiver {
    constructor () {
        console.info('Registering listener...');
        veryImportantThingsQueue.process(job => {
            console.info('Got a message from the queue with data:', job.data);
            return Promise.resolve({});
        });
    }
}

// Sends the date every 1.5 seconds
class Sender {
    constructor () {
        function sendMessage() {
            const messageValue = new Date();
            console.info('Sending a message...', messageValue);
            veryImportantThingsQueue.add({ 'key': messageValue });
        }

        setInterval(sendMessage, 1500);
    }
}

// Sanity check
if (process.argv.length < 2) {
    throw new Error(`Usage: ${process.argv.slice(2).join(' ')} <sender | receiver>`);
}

// Start either receiver or sender depending of CLI arg
console.info('Starting...');
if (process.argv[2] === 'sender') {
    new Sender();
} else if (process.argv[2] === 'receiver') {
    new Receiver();
} else {
    throw new Error(`Usage: ${process.argv.slice(0, 2).join(' ')} <sender | receiver>`);
}
```

# Dockerfile

这里没有什么特别的：这个文件基本上是我们旧的 Node.js 应用程序的精简版本：

```
FROM node:8

# Make sure we are fully up to date
RUN apt-get update -q && \
 apt-get dist-upgrade -y && \
 apt-get clean && \
 apt-get autoclean

# Container port that should get exposed
EXPOSE 8000

ENV SRV_PATH /usr/local/share/queue_handler

# Make our directory
RUN mkdir -p $SRV_PATH && \
 chown node:node $SRV_PATH

WORKDIR $SRV_PATH

USER node

COPY . $SRV_PATH/

RUN npm install

CMD ["npm", "start"]
```

我们现在将构建镜像：

```
$ docker build -t queue-worker .
Sending build context to Docker daemon  7.168kB
<snip>
 ---> 08e33a32ba60
Removing intermediate container e17c836c5a33
Successfully built 08e33a32ba60
Successfully tagged queue-worker:latest
```

通过构建镜像，我们现在可以编写我们的堆栈定义文件：`swarm_application.yml`。我们基本上是在单个网络上创建队列服务器、队列监听器和队列发送器，并确保它们可以在这里找到彼此：

```
version: "3"
services:
 queue-sender:
 image: queue-worker
 command: ["npm", "start", "sender"]
 networks:
 - queue_network
 deploy:
 replicas: 1
 depends_on:
 - redis-server
 environment:
 - QUEUE_HOST=redis-server

 queue-receiver:
 image: queue-worker
 command: ["npm", "start", "receiver"]
 networks:
 - queue_network
 deploy:
 replicas: 1
 depends_on:
 - redis-server
 environment:
 - QUEUE_HOST=redis-server

 redis-server:
 image: redis
 networks:
 - queue_network
 deploy:
 replicas: 1
 networks:
 - queue_network
 ports:
 - 6379:6379

networks:
 queue_network:
```

在镜像构建和堆栈定义都完成后，我们可以启动我们的队列集群，看看它是否正常工作：

```
$ # We need a Swarm first
$ docker swarm init
Swarm initialized: current node (c0tq34hm6u3ypam9cjr1vkefe) is now a manager.
<snip>

$ # Now we deploy our stack and name it "queue_stack"
$ docker stack deploy \
               -c swarm_application.yml \
               queue_stack
Creating service queue_stack_queue-sender
Creating service queue_stack_queue-receiver
Creating service queue_stack_redis-server

$ # At this point, we should be seeing some traffic...
$ docker service logs queue_stack_queue-receiver
<snip>
queue_stack_queue-receiver.1.ozk2uxqnbfqz@machine    | Starting...
queue_stack_queue-receiver.1.ozk2uxqnbfqz@machine    | Registering listener...
queue_stack_queue-receiver.1.ozk2uxqnbfqz@machine    | Got a message from the queue with data: { key: '2017-10-02T08:24:21.391Z' }
queue_stack_queue-receiver.1.ozk2uxqnbfqz@machine    | Got a message from the queue with data: { key: '2017-10-02T08:24:22.898Z' }
<snip>

$ # Yay! It's working!

$ # Let's clean things up to finish up
$ docker stack rm queue_stack
Removing service queue_stack_queue-receiver
Removing service queue_stack_queue-sender
Removing service queue_stack_redis-server
Removing network queue_stack_redis-server
Removing network queue_stack_queue_network
Removing network queue_stack_service_network

$ docker swarm leave --force
Node left the swarm.
```

在这一点上，我们可以添加任意数量的发送者和监听者（在合理范围内），我们的系统将以非常异步的方式正常工作，从而增加两端的吞吐量。不过，作为提醒，如果你决定走这条路，强烈建议使用另一种队列类型（如 Kafka、SQS 等），但基本原则基本上是相同的。

# 高级安全

我们在之前的章节中已经涵盖了一些安全问题，但对于一些似乎经常被忽视的问题，我们需要更深入地讨论它们，而不仅仅是在文本中间的小信息框中看到它们，并了解为什么当不正确使用时它们会成为如此严重的问题。虽然在实施我们在各种警告和信息框中指出的所有事情可能会显得很费力，但是你提供给潜在入侵者的攻击面越小，从长远来看你就会越好。也就是说，除非你正在为政府机构部署这个系统，我预计会有一些妥协，但我敦促你强烈权衡每个方面的利弊，否则你就有可能会收到那个可怕的午夜电话，通知你发生了入侵。

具有讽刺意味的是，加固系统通常需要花费大量时间来开发和部署，以至于它们往往在投入生产环境时已经过时或提供的业务价值较小，并且由于它们精心组装的部件，它们很少（如果有的话）会更新为新功能，迅速应用补丁，或对源代码进行改进，因此它真的是一把双刃剑。没有*完美的解决方案，只有一系列你在某种程度上感到舒适的事情。从历史上看，我大多数情况下看到的是在两个极端之间的可怕执行，所以我在这里的建议是，如果可能的话，你应该寻求两者的结合。

# 将 Docker 套接字挂载到容器中

这绝对是开发人员在部署容器化解决方案时完全忽视的最严重的安全漏洞。对于与容器管理相关的各种事情，通常在互联网上的建议都倾向于将 Docker 套接字（`/var/run/docker.sock`）绑定到容器中，但很少提到的是这样做实际上会有效地将主机的根级访问权限赋予这样的容器。由于 Docker 的套接字实际上只是一个 API 端点，而 Docker 守护程序以 root 身份运行，容器可以通过在其上挂载主机系统文件夹并在其上执行任意命令来简单地逃离其封闭环境。

有关使用 Docker 套接字作为 RESTful 端点的更多信息，您可以查看源代码，或者通过 Docker Engine API 的文档进行探索[`docs.docker.com/engine/api/v1.31/`](https://docs.docker.com/engine/api/v1.31/)。通常，您只需要通过诸如`curl`之类的工具添加`--unix-socket <socket_path>`，并且对于`POST`请求，可以选择添加`-H "Content-Type: application/json"`。

Docker 一直在努力将其服务从根级别转变为用户空间级别，但到目前为止，这个功能还没有以任何实际的方式实现。尽管我个人对这种情况很怀疑，但请留意这个功能，因为在某个时候它可能会真正发布并成为一个可用的功能，这将是容器安全性的重大进步。

```
$ Start a "benign" container with the Docker socket mounted and run Bash
$ docker run --rm \
 -it \
 -v /var/run/docker.sock:/var/run/docker.sock \
 ubuntu /bin/bash 

root@686212135a17:/# # Sanity check - make sure that the socket is there
root@686212135a17:/# ls -la /var/run/docker.sock
srw-rw---- 1 root 136 0 Sep 20 05:03 /var/run/docker.sock

root@686212135a17:/# # Install curl but almost any other HTTP client will work
root@686212135a17:/# # Even a base Python can do this but curl is fine for brevity
root@686212135a17:/# apt-get update && apt-get install -y curl
<snip>
done

root@686212135a17:/# # Create a container through the socket and bind-mount root to it
root@686212135a17:/# # with a "malicious" touch command to run
root@686212135a17:/# curl -s \
 --unix-socket /var/run/docker.sock \
 -H "Content-Type: application/json" \
 -d '{"Image": "ubuntu", "Cmd": ["touch", "/mnt/security_breach"], "Mounts": [{"Type": "bind", "Source": "/", "Target":"/mnt", "RW": true}]}' \
 -X POST \
 http:/v1.29/containers/create 
{"Id":"894c4838931767462173678aacc51c3bb98f4dffe15eaf167782513305c72558","Warnings":null}

root@686212135a17:/# # Start our escaped container
root@686212135a17:/# curl --unix-socket /var/run/docker.sock \
 -X POST \
 http:/v1.29/containers/894c4838/start

root@686212135a17:/# # Exit out of our "benign" container back to host
root@686212135a17:/# exit
exit

$ # Let's see what happened on our host
$ ls -la / | grep breach
-rw-r--r--   1 root root       0 Sep 20 23:14 security_breach 
$ # Oops!
```

现在应该很明显了，良性容器是如何能够仅通过几个 CLI 命令就在主机上获得 root 权限的。虽然其中一些是基于容器进程以 root 身份运行，但如果 Docker 组 ID 与容器中的非特权组冲突，可能也会出现相同的情况，但是除了这些细微之处，可以说，挂载 Docker 套接字而不完全理解其影响可能导致非常痛苦的违规行为。考虑到这一点，这种技术也有（虽然很少）合法的用途，所以在这里要慎重使用。

# 现在我们已经了解了如何滥用 Docker 套接字的理论，接下来我们将跳出容器，尽管我们不会真的对系统造成任何破坏：主机安全扫描。

作为增加部署安全性的一部分，Docker 发布了一个工具，可以帮助轻松识别运行 Docker Engine 的主机上最常见的安全问题，称为**Docker Bench for Security**。这个工具将扫描和验证配置中的大量可能的弱点，并以非常易于阅读的列表形式呈现出来。您可以像在 Docker Hub 上使用其他常规容器一样下载和运行这个镜像。

警告！此安全扫描需要许多权限（`--net host`、`--pid host`、Docker 套接字挂载等），我们已经讨论过这些权限通常是在主机上运行的一个非常糟糕的主意，因为它们为恶意行为者提供了一个相当大的攻击向量，但另一方面，扫描需要这些权限来检查您的设置。因此，我强烈建议在网络隔离的环境中克隆要测试的主机机器上运行这种类型的安全扫描，以防止扫描镜像被恶意修改而危及您的基础设施。

```
$ docker run --rm \
 -it \
 --net host \
 --pid host \
 --cap-add audit_control \
 -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
 -v /var/lib:/var/lib \
 -v /var/run/docker.sock:/var/run/docker.sock \
 -v /usr/lib/systemd:/usr/lib/systemd \
 -v /etc:/etc \
 docker/docker-bench-security
# ------------------------------------------------------------------------------
# Docker Bench for Security v1.3.3
#
# Docker, Inc. (c) 2015-
#
# Checks for dozens of common best-practices around deploying Docker containers in production.
# Inspired by the CIS Docker Community Edition Benchmark v1.1.0.
# ------------------------------------------------------------------------------

Initializing Mon Oct  2 00:03:29 CDT 2017

[INFO] 1 - Host Configuration
[WARN] 1.1  - Ensure a separate partition for containers has been created
[NOTE] 1.2  - Ensure the container host has been Hardened
date: invalid date '17-10-1 -1 month'
sh: out of range
sh: out of range
[PASS] 1.3  - Ensure Docker is up to date
[INFO]      * Using 17.09.0 which is current
[INFO]      * Check with your operating system vendor for support and security maintenance for Docker
[INFO] 1.4  - Ensure only trusted users are allowed to control Docker daemon
[INFO]      * docker:x:999
[WARN] 1.5  - Ensure auditing is configured for the Docker daemon
[WARN] 1.6  - Ensure auditing is configured for Docker files and directories - /var/lib/docker
[WARN] 1.7  - Ensure auditing is configured for Docker files and directories - /etc/docker
[INFO] 1.8  - Ensure auditing is configured for Docker files and directories - docker.service
<snip>
[PASS] 2.10 - Ensure base device size is not changed until needed
[WARN] 2.11 - Ensure that authorization for Docker client commands is enabled
[WARN] 2.12 - Ensure centralized and remote logging is configured
[WARN] 2.13 - Ensure operations on legacy registry (v1) are Disabled
[WARN] 2.14 - Ensure live restore is Enabled
[WARN] 2.15 - Ensure Userland Proxy is Disabled
<snip>
[PASS] 7.9  - Ensure CA certificates are rotated as appropriate (Swarm mode not enabled)
[PASS] 7.10 - Ensure management plane traffic has been separated from data plane traffic (Swarm mode not enabled)
```

列表相当长，因此大部分输出行都被删除了，但你应该对这个工具的功能和如何使用有一个相当好的了解。请注意，这不是这个领域唯一的产品（例如，CoreOS 的 Clair 在 [`github.com/coreos/clair`](https://github.com/coreos/clair)），因此尽量使用尽可能多的产品，以便了解基础设施的弱点所在。

# 只读容器

在我们之前的示例开发中，跨越了大部分章节，我们并没有真正关注容器在运行时是否改变了文件系统的状态。这对于测试和开发系统来说并不是问题，但在生产环境中，进一步加强锁定非常重要，以防止来自内部和外部来源的恶意运行时利用。为此，有一个 `docker run --read-only` 标志，它（不出所料地）将容器的根文件系统挂载为只读。通过这样做，我们确保除了使用卷挂载的数据外，所有数据都与构建镜像时一样纯净，确保一致性并保护您的集群。如果以这种方式运行容器，您唯一需要注意的是，容器在执行过程中极有可能需要临时存储文件的位置，例如 `/run`、`/tmp` 和 `/var/tmp`，因此这些挂载应该额外作为 `tmpfs` 卷挂载：

```
$ # Start a regular container
$ docker run -it \
 --rm \
 ubuntu /bin/bash 
root@79042a966943:/# # Write something to /bin
root@79042a966943:/# echo "just_a_test" > /bin/test

root@79042a966943:/# # Check if it's there
root@79042a966943:/# ls -la /bin | grep test
-rw-r--r-- 1 root root      12 Sep 27 17:43 test

root@79042a966943:/# exit
exit

$ # Now try a read-only container
$ docker run -it \
 --rm \
 --tmpfs /run \
 --tmpfs /tmp \
 --tmpfs /var/tmp \
 --read-only \
 ubuntu /bin/bash 
root@5b4574a46c09:/# # Try to write to /bin
root@5b4574a46c09:/# echo "just_a_test" > /bin/test
bash: /bin/test: Read-only file system

root@5b4574a46c09:/# # Works as expected! What about /tmp?
root@5b4574a46c09:/# echo "just_a_test" > /tmp/test
root@5b4574a46c09:/# ls /tmp
test

root@5b4574a46c09:/# exit
exit
```

如果您不希望容器在文件系统上做出任何更改，并且由于容器通常不需要写入 `/usr` 等路径，强烈建议在生产中使用此标志，因此如果可能的话，请在所有静态服务上广泛应用它。

# 基础系统（软件包）更新

我们之前已经谈到了这个问题，但似乎在大多数在线文档和博客中，Docker 容器环境中软件包更新的覆盖范围被严重忽视。虽然支持者有两种观点，但重要的是要记住，无法保证来自 Docker Hub 等地方可用的标记图像是否已经使用最新的更新构建，即使在这些情况下，标记图像可能已经建立了一段时间，因此不包含最新的安全补丁。

尽管在 Docker 容器中使用主机的内核来运行容器的上下文是真实的，但容器中任何支持库的安全漏洞通常会导致漏洞，这些漏洞经常会级联到主机和整个网络中。因此，我个人建议部署到生产环境的容器应该尽可能确保使用最新的库构建容器。手动升级一些基本镜像上的软件包存在明显的风险，这是由于升级时可能会出现库不兼容性，但总的来说，这是一个值得冒的风险。

在大多数情况下，为了进行这种升级，就像我们在大多数 Docker 示例中所介绍的那样，你基本上需要在`Dockerfile`中调用特定于镜像基本操作系统发行版的系统升级命令。对于我们默认的部署操作系统（Ubuntu LTS），可以使用`apt-get update`和`apt-get dist-upgrade`来完成此操作。

```
...
RUN apt-get update && apt-get -y dist-upgrade
...
```

注意！不要忘记，默认情况下，`docker build`将缓存所有未更改的`Dockerfile`指令的各个层，因此该命令在第一次使用时会按预期工作，但如果它之前的任何行都没有更改，那么在后续使用时将从缓存中提取其层，因为这行将保持不变，而不管上游包是否更改。如果要确保获取最新更新，必须通过更改`Dockerfile`中`apt-get`上面的行或在`docker build`命令中添加`--no-cache`来打破缓存。此外，请注意，使用`--no-cache`将重新生成所有层，可能会导致较长的构建周期和/或注册表磁盘使用。

# 特权模式与--cap-add 和--cap-drop

在容器内可能需要执行的一些高级操作，例如**Docker-in-Docker（DinD）**、NTP、挂载回环设备等，都需要比默认情况下容器的根用户所拥有的更高权限。因此，需要为容器允许额外的权限，以便它能够无问题地运行，因此，对于这种情况，Docker 有一个非常简单但非常广泛的特权模式，它将主机的完整功能添加到容器中。要使用此模式，只需在`docker run`命令后附加`--privileged`：

**Docker-in-Docker**（通常称为**DinD**）是容器的特殊配置，允许您在已在 Docker 引擎上运行的容器内运行 Docker 引擎，但不共享 Docker 套接字，这允许（如果采取预防措施）更安全和更可靠地在已容器化的基础架构中构建容器。这种配置的普及程度有些罕见，但在**持续集成**（**CI**）和**持续交付**（**CD**）设置的一部分时非常强大。

```
$ # Run an NTP daemon without the extra privileges and see what happens
$ docker run -it \
 --rm \
 cguenther/ntpd 
ntpd: can't set priority: Permission denied
reset adjtime failed: Operation not permitted
creating new /var/db/ntpd.drift
adjtimex failed: Operation not permitted
adjtimex adjusted frequency by 0.000000ppm
ntp engine ready
reply from 38.229.71.1: offset -2.312472 delay 0.023870, next query 8s
settimeofday: Operation not permitted
reply from 198.206.133.14: offset -2.312562 delay 0.032579, next query 8s
reply from 96.244.96.19: offset -2.302669 delay 0.035253, next query 9s
reply from 66.228.42.59: offset -2.302408 delay 0.035170, next query 7s
^C

$ And now with our new privileged mode
$ docker run -it \
 --rm \
 --privileged \
 cguenther/ntpd 
creating new /var/db/ntpd.drift
adjtimex adjusted frequency by 0.000000ppm
ntp engine ready
^C
```

正如您所看到的，添加此标志将从输出中删除所有错误，因为我们现在可以更改系统时间。

解释了此模式的功能后，我们现在可以谈论为什么在理想情况下，如果可能的话，您永远不应该使用特权模式。默认情况下，特权模式几乎允许访问主机系统的所有内容，并且在大多数情况下不够细粒度，因此在确定容器需要额外权限后，应该使用`--cap-add`有选择地添加它们。这些标志是标准的 Linux 功能标识符，您可以在[`man7.org/linux/man-pages/man7/capabilities.7.html`](http://man7.org/linux/man-pages/man7/capabilities.7.html)等地方找到，并允许对所需的访问级别进行微调。如果我们现在将先前的 NTP 守护程序示例转换为这种新样式，它应该看起来更像这样：

```
$ # Sanity check
$ docker run -it \
 --rm \
 cguenther/ntpd 
ntpd: can't set priority: Permission denied
<snip>
settimeofday: Operation not permitted
<snip>
^C

$ # Now with the added SYS_TIME capability
$ docker run -it \
 --rm \
 --cap-add SYS_TIME \
 cguenther/ntpd 
ntpd: can't set priority: Permission denied
creating new /var/db/ntpd.drift
adjtimex adjusted frequency by 0.000000ppm
ntp engine ready
reply from 204.9.54.119: offset 15.805277 delay 0.023080, next query 5s
set local clock to Mon Oct  2 06:05:47 UTC 2017 (offset 15.805277s)
reply from 38.229.71.1: offset 0.005709 delay 31.617842, next query 9s
^C
```

如果您注意到，由于另一个缺失的功能，我们仍然有一个可见的错误，但`settimeofday`错误已经消失了，这是我们需要解决的最重要的问题，以便该容器能够运行。

有趣的是，我们还可以使用`--cap-drop`从容器中删除未被使用的功能，以增加安全性。对于这个标志，还有一个特殊的关键字`ALL`，可以用来删除所有可用的权限。如果我们使用这个来完全锁定我们的 NTP 容器，但一切正常运行，让我们看看会是什么样子：

```
docker run -it \
 --rm \
 --cap-drop ALL \
 --cap-add SYS_TIME \
 --cap-add SYS_CHROOT \
 --cap-add SETUID \
 --cap-add SETGID \
 --cap-add SYS_NICE \
 cguenther/ntpd 
creating new /var/db/ntpd.drift
adjtimex adjusted frequency by 0.000000ppm
ntp engine ready
reply from 216.229.0.49: offset 14.738336 delay 1.993620, next query 8s
set local clock to Mon Oct  2 06:16:09 UTC 2017 (offset 14.738336s)
reply from 216.6.2.70: offset 0.523095 delay 30.422572, next query 6s
^C
```

在这里，我们首先删除了所有的功能，然后再添加回运行容器所需的少数功能，正如您所看到的，一切都运行正常。在您自己的部署中，我强烈建议，如果您有多余的开发能力或者注重安全性，花一些时间以这种方式锁定正在运行的容器，这样它们将更加安全，您也将更加确信容器是在最小权限原则下运行的。

“最小权限原则”是计算机安全中的一个概念，它只允许用户或服务运行组件所需的最低权限。这个原则在高安全性实现中非常重要，但通常在其他地方很少见，因为管理访问的开销被认为很大，尽管这是增加系统安全性和稳定性的好方法。如果您想了解更多关于这个概念的信息，您应该去[`en.wikipedia.org/wiki/Principle_of_least_privilege`](https://en.wikipedia.org/wiki/Principle_of_least_privilege)查看一下。

# 总结

在本章中，我们学习了许多部署强大集群所需的高级工具和技术，例如以下内容：

+   管理容器问题的额外调试选项。

+   深入研究 Docker 的高级网络主题。

+   实施我们自己的队列消息传递。

+   各种安全加固技巧和窍门。

所有这些主题加上之前的材料应该涵盖了大多数集群的部署需求。但在下一章中，我们将看到当主机、服务和任务的数量达到通常不被期望的水平时，我们需要担心什么问题，以及我们可以采取什么措施来减轻这些问题。


# 第七章：扩展的限制和解决方法

当您扩展系统时，您使用的每个工具或框架都会达到一个破坏或不按预期运行的点。对于某些事物，这一点可能很高，对于某些事物，这一点可能很低，本章的目的是介绍在使用微服务集群时可能遇到的最常见的可扩展性问题的策略和解决方法。在本章中，我们将涵盖以下主题：

+   增加服务密度和稳定性。

+   避免和减轻大规模部署中的常见问题。

+   多服务容器。

+   零停机部署的最佳实践。

# 限制服务资源

到目前为止，我们并没有真正花时间讨论与服务可用资源相关的服务隔离，但这是一个非常重要的话题。如果不限制资源，恶意或行为不端的服务可能会导致整个集群崩溃，具体取决于严重程度，因此需要非常小心地指定个别服务任务应该使用的资源限额。

处理集群资源的通常接受的策略如下：

+   任何资源如果超出预期值使用可能会导致其他服务出现错误或故障，强烈建议在服务级别上进行限制。这通常是 RAM 分配，但也可能包括 CPU 或其他资源。

+   任何资源，特别是硬件资源，都应该在 Docker 容器中进行限制（例如，您只能使用 1-Gbps NAS 连接的特定部分）。

+   任何需要在特定设备、机器或主机上运行的东西都应以相同的方式锁定到这些资源上。当只有一定数量的机器具有适合某项服务的正确硬件时，这种设置非常常见，比如在 GPU 计算集群中。

+   通常应该对希望在集群中特别配给的任何资源施加限制。这包括降低低优先级服务的 CPU 时间百分比等事项。

+   在大多数情况下，其余资源应该可以正常使用主机可用资源的正常分配。

通过应用这些规则，我们将确保我们的集群更加稳定和安全，资源的分配也更加精确。此外，如果指定了服务所需的确切资源，编排工具通常可以更好地决定在哪里安排新创建的任务，以便最大化每个引擎的服务密度。

# RAM 限制

奇怪的是，尽管 CPU 可能被认为是最重要的计算资源，但由于 RAM 的过度使用可能会导致内存不足（OOM）进程和任务失败，因此对集群服务的 RAM 分配甚至更为重要。由于软件中内存泄漏的普遍存在，这通常不是“是否”而是“何时”的问题，因此设置 RAM 分配限制通常是非常可取的，在某些编排配置中甚至是强制性的。遇到这个问题通常会看到`SIGKILL`，`"进程被杀死"`或`退出代码-9`。

请记住，这些信号很可能是由其他原因引起的，但最常见的原因是 OOM 失败。

通过限制可用的 RAM，而不是由 OOM 管理器杀死主机上的随机进程，只有有问题的任务进程将被定位为目标，因此可以更容易和更快地识别出有问题的代码，因为您可以看到来自该服务的大量失败，而您的其他服务将保持运行，增加了集群的稳定性。

OOM 管理是一个庞大的主题，比起在本节中包含它更明智，但如果您在 Linux 内核中花费大量时间，了解这一点非常重要。如果您对此主题感兴趣，我强烈建议您访问[`www.kernel.org/doc/gorman/html/understand/understand016.html`](https://www.kernel.org/doc/gorman/html/understand/understand016.html)并对其进行阅读。警告！在一些最流行的内核上，由于其开销，内存和/或交换 cgroups 被禁用。要在这些内核上启用内存和交换限制，您的主机内核必须以`cgroup_enable=memory`和`swapaccount=1`标志启动。如果您使用 GRUB 作为引导加载程序，您可以通过编辑`/etc/default/grub`（或者在最新系统上，`/etc/default/grub.d/<name>`），设置`GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1"`，运行`sudo update-grub`，然后重新启动您的机器来启用它们。

要使用限制 RAM 的`cgroup`配置，运行容器时使用以下标志的组合：

+   -m / --内存：容器可以使用的最大内存量的硬限制。超过此限制的新内存分配将失败，并且内核将终止容器中通常运行服务的主要进程。

+   --内存交换：容器可以使用的包括交换在内的内存总量。这必须与前一个选项一起使用，并且比它大。默认情况下，容器最多可以使用两倍于容器的允许内存的内存。将其设置为`-1`允许容器使用主机拥有的交换空间。

+   --内存交换倾向：系统将页面从物理内存移动到磁盘交换空间的渴望程度。该值介于`0`和`100`之间，其中`0`表示页面将尽可能留在驻留 RAM 中，反之亦然。在大多数机器上，该值为`80`，将用作默认值，但由于与 RAM 相比，交换空间访问非常缓慢，我的建议是将此数字设置为尽可能接近`0`。

+   --内存预留：服务的 RAM 使用的软限制，通常仅用于检测资源争用，以便编排引擎可以安排任务以实现最大使用密度。此标志不能保证将保持服务的 RAM 使用量低于此水平。

还有一些其他标志可以用于内存限制，但即使前面的列表可能比你需要担心的要详细一些。对于大多数部署，无论大小，你可能只需要使用`-m`并设置一个较低的值`--memory-swappiness`，后者通常是通过`sysctl.d`引导设置在主机上完成的，以便所有服务都将利用它。

你可以通过运行`sysctl vm.swappiness`来检查你的`swappiness`设置是什么。如果你想改变这个值，在大多数集群部署中你会这样做，你可以通过运行以下命令来设置这个值：

`$ echo "vm.swappiness = 10" | sudo tee -a /etc/sysctl.d/60-swappiness.conf`

要看到这一点的实际效果，我们首先将运行一个最资源密集的框架（JBoss），限制为 30 MB 的 RAM，看看会发生什么：

```
$ docker run -it \
             --rm \
             -m 30m \
             jboss/wildfly 
Unable to find image 'jboss/wildfly:latest' locally
latest: Pulling from jboss/wildfly
<snip>
Status: Downloaded newer image for jboss/wildfly:latest
=========================================================================

 JBoss Bootstrap Environment

 JBOSS_HOME: /opt/jboss/wildfly

 JAVA: /usr/lib/jvm/java/bin/java

 JAVA_OPTS:  -server -Xms64m -Xmx512m -XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m -Djava.net.preferIPv4Stack=true -Djboss.modules.system.pkgs=org.jboss.byteman -Djava.awt.headless=true

=========================================================================

* JBossAS process (57) received KILL signal *
```

不出所料，容器使用了太多的 RAM，并立即被内核杀死。现在，如果我们尝试相同的事情，但给它 400 MB 的 RAM 呢？

```

$ docker run -it \
             --rm \
             -m 400m \
             jboss/wildfly
=========================================================================

 JBoss Bootstrap Environment

 JBOSS_HOME: /opt/jboss/wildfly

 JAVA: /usr/lib/jvm/java/bin/java

 JAVA_OPTS:  -server -Xms64m -Xmx512m -XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m -Djava.net.preferIPv4Stack=true -Djboss.modules.system.pkgs=org.jboss.byteman -Djava.awt.headless=true

=========================================================================

14:05:23,476 INFO  [org.jboss.modules] (main) JBoss Modules version 1.5.2.Final
<snip>
14:05:25,568 INFO  [org.jboss.ws.common.management] (MSC service thread 1-6) JBWS022052: Starting JBossWS 5.1.5.Final (Apache CXF 3.1.6) 
14:05:25,667 INFO  [org.jboss.as] (Controller Boot Thread) WFLYSRV0060: Http management interface listening on http://127.0.0.1:9990/management
14:05:25,667 INFO  [org.jboss.as] (Controller Boot Thread) WFLYSRV0051: Admin console listening on http://127.0.0.1:9990
14:05:25,668 INFO  [org.jboss.as] (Controller Boot Thread) WFLYSRV0025: WildFly Full 10.1.0.Final (WildFly Core 2.2.0.Final) started in 2532ms - Started 331 of 577 services (393 services are lazy, passive or on-demand)
```

我们的容器现在可以无问题地启动了！

如果你在裸机环境中大量使用应用程序，你可能会问自己为什么 JBoss JVM 事先不知道它将无法在如此受限制的环境中运行并更早地失败。答案在于`cgroups`的一个非常不幸的怪癖（尽管我认为它可能被视为一个特性，取决于你的观点），它将主机的资源未经修改地呈现给容器，即使容器本身受到限制。如果你运行一个内存受限的容器并打印出可用的 RAM 限制，你很容易看到这一点：

```
$ # Let's see what a low allocation shows
$ docker run -it --rm -m 30m ubuntu /usr/bin/free -h
 total        used        free      shared  buff/cache   available
Mem:           7.6G        1.4G        4.4G         54M        1.8G        5.9G
Swap:            0B          0B          0B

$ # What about a high one?
$ docker run -it --rm -m 900m ubuntu /usr/bin/free -h
 total        used        free      shared  buff/cache   available
Mem:           7.6G        1.4G        4.4G         54M        1.8G        5.9G
Swap:            0B          0B          0B
```

正如你所想象的，这会导致在这样一个`cgroup`受限制的容器中启动的应用程序出现各种级联问题，主要问题是应用程序根本不知道有限制，因此它会尝试做它的工作，假设它可以完全访问可用的 RAM。一旦应用程序达到预定义的限制，应用程序进程通常会被杀死，容器也会死掉。这是一个巨大的问题，对于可以对高内存压力做出反应的应用程序和运行时来说，它们可能能够在容器中使用更少的 RAM，但因为它们无法确定它们正在受到限制，它们倾向于以比应该更高的速率吞噬内存。

遗憾的是，对于容器来说，情况甚至更糟。你不仅必须给服务一个足够大的 RAM 限制来启动它，还必须足够大，以便它可以处理在服务的整个持续时间内动态分配的内存。如果不这样做，同样的情况将在一个不太可预测的时间发生。例如，如果你只给一个 NGINX 容器 4MB 的 RAM 限制，它会正常启动，但在连接到它的几次后，内存分配将超过阈值，容器将死机。然后服务可能会重新启动任务，除非你有日志记录机制或你的编排提供了良好的工具支持，否则你最终会得到一个状态为“运行”的服务，但实际上它无法处理任何请求。

如果这还不够，你也真的不应该随意地分配高限制。这是因为容器的一个目的是在给定的硬件配置下最大化服务密度。通过设置几乎不可能被运行服务达到的限制，你实际上在浪费这些资源，因为它们无法被其他服务使用。从长远来看，这会增加基础设施的成本和维护所需的资源，因此有很大的动力来保持服务受到最低限度的限制，以确保安全运行，而不是使用非常高的限制。

编排工具通常可以防止资源过度分配，尽管 Docker Swarm 和 Kubernetes 都在支持这一特性方面取得了一些进展，你可以指定软限制（内存请求）与真实限制（内存限制）。然而，即使有了这些参数，调整 RAM 设置仍然是一个非常具有挑战性的任务，因为你可能会出现资源利用不足或持续重新调度的情况，因此这里涉及的所有主题仍然非常相关。关于编排特定处理资源过度分配的更多信息，我建议你阅读你特定编排工具的最新文档。

因此，当考虑所有必须牢记的事情时，调整限制更接近于一种艺术形式，而不是其他任何东西，因为它几乎就像著名的装箱问题的变体（[`en.wikipedia.org/wiki/Bin_packing_problem`](https://en.wikipedia.org/wiki/Bin_packing_problem)），但也增加了服务的统计组件，因为您可能需要找出最佳的服务可用性与由于宽松限制而浪费资源之间的平衡。

假设我们有一个以下分布的服务：

+   每个物理主机的 RAM 为 2 GB（是的，这确实很低，但这是为了演示小规模问题）

+   **服务 1**（数据库）的内存限制为 1.5 GB，有两个任务，并且有 1%的几率超过硬限制运行

+   **服务 2**（应用程序）的内存限制为 0.5 GB，有三个任务，并且有 5%的几率超过硬限制运行

+   **服务 3**（数据处理服务）的内存限制为 0.5 GB，有三个任务，并且有 5%的几率超过硬限制运行

调度程序可以按以下方式分配服务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/39e05686-46b7-42f2-bb8b-446d34e67613.png)警告！您应该始终在集群上保留一定的容量以进行滚动服务更新，因此在实际情况下，配置与图表中所示的类似配置效果不佳。通常，这种额外的容量也是一个模糊值，就像 RAM 限制一样。通常，我的公式如下，但随时可以根据需要进行调整：

`过剩容量=平均（服务大小）*平均（服务计数）*平均（最大滚动服务重启）`

我们将在文本中进一步讨论这一点。

如果我们拿最后一个例子，现在说我们应该只在整体上以 1%的 OOM 故障率运行，将我们的**服务 2**和**服务 3**的内存限制从 0.5 GB 增加到 0.75 GB，而不考虑也许在数据处理服务和应用程序任务上具有更高的故障率可能是可以接受的（甚至如果您使用消息队列，最终用户可能根本不会注意到）？

新的服务分布现在看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dpl-dkr/img/c864d401-c786-4c00-9c1d-b6b70a6b8160.png)

我们的新配置存在大量明显的问题：

+   服务密度减少 25%。这个数字应该尽可能高，以获得使用微服务的所有好处。

+   硬件利用率减少了 25％。实际上，在这种设置中，可用硬件资源的四分之一被浪费。

+   节点数量增加了 66％。大多数云服务提供商按照运行的机器数量收费，假设它们是相同类型的。通过进行这种改变，您实际上增加了 66％的云成本，并可能需要额外的运维支持来保持集群的运行。

尽管这个例子是故意操纵的，以便在调整时产生最大的影响，但显而易见的是，对这些限制进行轻微的更改可能会对整个基础设施产生巨大的影响。在实际场景中，这种影响将会减少，因为主机机器会更大，这将使它们更能够在可用空间中堆叠较小（相对于总容量）的服务，*不要*低估增加服务资源分配的级联效应。

# CPU 限制

就像我们之前关于服务内存限制的部分一样，`docker run`也支持各种 CPU 设置和参数，以调整您的服务的计算需求：

+   `-c`/`--cpu-shares`：在高负载主机上，默认情况下所有任务的权重都是相等的。在任务或服务上设置此标志（从默认值`1024`）将增加或减少任务可以被调度的 CPU 利用率的百分比。

+   `--cpu-quota`：此标志设置任务或服务在默认的 100 毫秒（100,000 微秒）时间块内可以使用 CPU 的微秒数。例如，要仅允许任务最多使用单个 CPU 核心 50％的使用率，您将把此标志设置为`50000`。对于多个核心，您需要相应地增加此值。

+   `--cpu-period`：这会更改以微秒为单位的先前配额标志默认间隔，用于评估`cpu-quota`（100 毫秒/100,000 微秒），并将其减少或增加以反向影响服务的 CPU 资源分配。

+   `--cpus`：一个浮点值，结合了`cpu-quota`和`cpu-period`的部分，以限制任务对 CPU 核分配的数量。例如，如果您只希望任务最多使用四分之一的单个 CPU 资源，您可以将其设置为`0.25`，它将产生与`--cpu-quota 25000 --cpu-period 100000`相同的效果。

+   `--cpuset-cpus`：此数组标志允许服务仅在从 0 开始索引的指定 CPU 上运行。如果您希望服务仅使用 CPU 0 和 3，您可以使用`--cpuset-cpus "0,3"`。此标志还支持将值输入为范围（即`1-3`）。

虽然可能看起来有很多选项需要考虑，但在大多数情况下，您只需要调整`--cpu-shares`和`--cpus`标志，但有可能您需要更精细地控制它们提供的资源。

我们来看看`--cpu-shares`值对我们有什么作用？为此，我们需要模拟资源争用，在下一个示例中，我们将尝试通过在机器上的每个 CPU 上增加一个整数变量的次数来在 60 秒内尽可能多地模拟这一点。代码有点复杂，但其中大部分是为了使 CPU 在所有核心上达到资源争用水平。

将以下内容添加到名为`cpu_shares.sh`的文件中（也可在[`github.com/sgnn7/deploying_with_docker`](https://github.com/sgnn7/deploying_with_docker)上找到）：

```
#!/bin/bash -e

CPU_COUNT=$(nproc --all)
START_AT=$(date +%s)
STOP_AT=$(( $START_AT + 60 ))

echo "Detected $CPU_COUNT CPUs"
echo "Time range: $START_AT -> $STOP_AT"

declare -a CONTAINERS

echo "Allocating all cores but one with default shares"
for ((i = 0; i < $CPU_COUNT - 1; i++)); do
  echo "Starting container $i"
  CONTAINERS[i]=$(docker run \
                  -d \
                  ubuntu \
                  /bin/bash -c "c=0; while [ $STOP_AT -gt \$(date +%s) ]; do c=\$((c + 1)); done; echo \$c")
done

echo "Starting container with high shares"
  fast_task=$(docker run \
              -d \
              --cpu-shares 8192 \
              ubuntu \
              /bin/bash -c "c=0; while [ $STOP_AT -gt \$(date +%s) ]; do c=\$((c + 1)); done; echo \$c")

  CONTAINERS[$((CPU_COUNT - 1))]=$fast_task

echo "Waiting full minute for containers to finish..."
sleep 62

for ((i = 0; i < $CPU_COUNT; i++)); do
  container_id=${CONTAINERS[i]}
  echo "Container $i counted to $(docker logs $container_id)"
  docker rm $container_id >/dev/null
done
```

现在我们将运行此代码并查看我们标志的效果：

```
$ # Make the file executable
$ chmod +x ./cpu_shares.sh

$ # Run our little program
$ ./cpu_shares.sh
Detected 8 CPUs
Time range: 1507405189 -> 1507405249
Allocating all cores but one with default shares
Starting container 0
Starting container 1
Starting container 2
Starting container 3
Starting container 4
Starting container 5
Starting container 6
Starting container with high shares
Waiting full minute for containers to finish...
Container 0 counted to 25380
Container 1 counted to 25173
Container 2 counted to 24961
Container 3 counted to 24882
Container 4 counted to 24649
Container 5 counted to 24306
Container 6 counted to 24280
Container 7 counted to 31938
```

尽管具有较高`--cpu-share`值的容器没有得到预期的完全增加，但如果我们在更长的时间内使用更紧密的 CPU 绑定循环运行基准测试，差异将会更加明显。但即使在我们的小例子中，您也可以看到最后一个容器在机器上运行的所有其他容器中具有明显优势。

为了了解`--cpus`标志的作用，让我们看看在一个没有争用的系统上它能做什么：

```
$ # First without any limiting
$ time docker run -it \
 --rm \
 ubuntu \
 /bin/bash -c 'for ((i=0; i<100; i++)); do sha256sum /bin/bash >/dev/null; done'
real    0m1.902s
user    0m0.030s
sys    0m0.006s

$ # Now with only a quarter of the CPU available
$ time docker run -it \
 --rm \
 --cpus=0.25 \
 ubuntu \
 /bin/bash -c 'for ((i=0; i<100; i++)); do sha256sum /bin/bash >/dev/null; done'
real    0m6.456s
user    0m0.018s
sys    0m0.017s
```

正如您所看到的，`--cpus`标志非常适合确保任务不会使用超过指定值的 CPU，即使在机器上没有资源争用的情况下。

请记住，还有一些限制容器资源使用的选项，这些选项有些超出了我们已经涵盖的一般范围，但它们主要用于特定设备的限制（例如设备 IOPS）。如果您有兴趣了解如何将资源限制到任务或服务的所有可用方式，您应该能够在[`docs.docker.com/engine/reference/run/#runtime-constraints-on-resources`](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)找到它们。

# 避免陷阱

在大多数小型和中型部署中，您永远不会遇到与扩展超出它们时会开始遇到的相同问题，因此本节旨在向您展示您将遇到的最常见问题以及如何以最干净的方式解决它们。虽然这个列表应该涵盖您将遇到的大多数突出问题，但您自己的一些问题将需要自定义修复。您不应该害怕进行这些更改，因为几乎所有主机操作系统安装都不适合高负载多容器所需的配置。

警告！本节中的许多值和调整都是基于在云中部署 Docker 集群的个人经验。根据您的云提供商、操作系统分发和基础设施特定配置的组合，这些值可能不需要从默认值更改，有些甚至可能对系统造成损害，如果直接使用而不花时间学习它们的含义和如何修改。如果您继续阅读本节，请将示例仅用作更改值的示例，而不是直接复制/粘贴到配置管理工具中。

# ulimits

`ulimit`设置对大多数 Linux 桌面用户来说是鲜为人知的，但在与服务器工作时，它们是一个非常痛苦且经常遇到的问题。简而言之，`ulimit`设置控制了进程资源使用的许多方面，就像我们之前介绍的 Docker 资源调整一样，并应用于已启动的每个进程和 shell。这些限制几乎总是在发行版上设置的，以防止一个杂乱的进程使您的机器崩溃，但这些数字通常是根据常规桌面使用而选择的，因此尝试在未更改的系统上运行服务器类型的代码几乎肯定会至少触及打开文件限制，可能还会触及其他一些限制。

我们可以使用`ulimit -a`来查看我们当前（也称为**软限制**）的设置：

```
$ ulimit -a
core file size          (blocks, -c) 0
data seg size           (kbytes, -d) unlimited
scheduling priority             (-e) 0
file size               (blocks, -f) unlimited
pending signals                 (-i) 29683
max locked memory       (kbytes, -l) 64
max memory size         (kbytes, -m) unlimited
open files                      (-n) 1024
pipe size            (512 bytes, -p) 8
POSIX message queues     (bytes, -q) 819200
real-time priority              (-r) 0
stack size              (kbytes, -s) 8192
cpu time               (seconds, -t) unlimited
max user processes              (-u) 29683
virtual memory          (kbytes, -v) unlimited
file locks                      (-x) unlimited
```

正如您所看到的，这里只设置了一些东西，但有一项突出：我们的“打开文件”限制（`1024`）对于一般应用程序来说是可以的，但如果我们运行许多处理大量打开文件的服务（例如相当数量的 Docker 容器），这个值必须更改，否则您将遇到错误，您的服务将有效地停止运行。

您可以使用`ulimit -S <flag> <value>`来更改当前 shell 的值：

```
$ ulimit -n
1024

$ # Set max open files to 2048
$ ulimit -S -n 2048

$ # Let's see the full list again
$ ulimit -a
<snip>
open files                      (-n) 2048
<snip>
```

但是，如果我们尝试将其设置为非常高的值会怎样呢？

```
$ ulimit -S -n 10240
bash: ulimit: open files: cannot modify limit: Invalid argument
```

在这里，我们现在遇到了系统强加的硬限制。如果我们想要修改超出这些值，这个限制是需要在系统级别进行更改的。我们可以使用`ulimit -H -a`来检查这些硬限制是什么：

```
$ ulimit -H -a | grep '^open files'
open files                      (-n) 4096
```

因此，如果我们想要增加我们的打开文件数超过`4096`，我们确实需要更改系统级设置。此外，即使`4086`的软限制对我们来说没问题，该设置仅适用于我们自己的 shell 及其子进程，因此不会影响系统上的任何其他服务或进程。

如果你真的想要，你实际上可以使用`util-linux`软件包中的`prlimit`更改已运行进程的`ulimit`设置，但不鼓励使用这种调整值的方法，因为这些设置在进程重新启动期间不会持续，因此对于这个目的而言是相当无用的。话虽如此，如果你想要找出你的`ulimit`设置是否已应用于已经运行的服务，这个 CLI 工具是非常宝贵的，所以在这些情况下不要害怕使用它。

要更改此设置，您需要根据您的发行版进行一系列选项的组合：

+   创建一个安全限制配置文件。你可以通过向`/etc/security/limits.d/90-ulimit-open-files-increase.conf`添加几行来简单地做到这一点。以下示例将`root`的打开文件软限制设置为`65536`，然后设置所有其他账户（`*`不适用于`root`账户）的限制。你应该提前找出你的系统的适当值是多少。

```
root soft nofile 65536
root hard nofile 65536
* soft nofile 65536
* hard nofile 65536
```

+   将`pam_limits`模块添加到**可插拔认证模块**（**PAM**）。这将影响所有用户会话以前的`ulimit`更改设置，因为一些发行版没有包含它，否则你的更改可能不会持续。将以下内容添加到`/etc/pam.d/common-session`：

```
session required pam_limits.so
```

+   或者，在一些发行版上，你可以直接在`systemd`中的受影响服务定义中添加设置到覆盖文件中：

```
LimitNOFILE=65536
```

覆盖`systemd`服务是本节中一个相当冗长和分散注意力的话题，但它是一个非常常见的策略，用于调整在具有该 init 系统的集群部署上运行的第三方服务，因此这是一个非常有价值的技能。如果您想了解更多关于这个话题的信息，您可以在[`askubuntu.com/a/659268`](https://askubuntu.com/a/659268)找到该过程的简化版本，如果您想要详细版本，可以在[`www.freedesktop.org/software/systemd/man/systemd.service.html`](https://www.freedesktop.org/software/systemd/man/systemd.service.html)找到上游文档。注意！在第一个例子中，我们使用了`*`通配符，它影响了机器上的所有账户。通常，出于安全原因，您希望将此设置隔离到仅受影响的服务账户，如果可能的话。我们还使用了`root`，因为在一些发行版中，根值是通过名称专门设置的，这会由于更高的特异性而覆盖`*`通配符设置。如果您想了解更多关于限制的信息，您可以在[`linux.die.net/man/5/limits.conf`](https://linux.die.net/man/5/limits.conf)找到更多信息。

# 最大文件描述符

就像我们对会话和进程有最大打开文件限制一样，内核本身对整个系统的最大打开文件描述符也有限制。如果达到了这个限制，就无法打开其他文件，因此在可能同时打开大量文件的机器上需要进行调整。

这个值是内核参数的一部分，因此可以使用`sysctl`命令查看：

```
$ sysctl fs.file-max
fs.file-max = 757778
```

虽然在这台机器上这个值似乎是合理的，但我曾经看到一些旧版本的发行版具有令人惊讶的低值，如果您在系统上运行了大量容器，很容易出现错误。

我们在这里和本章后面讨论的大多数内核配置设置都可以使用`sysctl -w <key>="<value>"`进行临时更改。然而，由于这些值在每次重新启动时都会重置为默认值，它们通常对我们没有长期用途，因此这里不会涉及到它们，但请记住，如果您需要调试实时系统或应用临时的时间敏感的修复，您可以使用这些技术。

要更改此值以使其在重新启动后保持不变，我们需要将以下内容添加到`/etc/sysctl.d`文件夹中（即`/etc/sysctl.d/10-file-descriptors-increase.conf`）：

```
fs.file-max = 1000000
```

更改后，重新启动，您现在应该能够在机器上打开多达 100 万个文件句柄！

# 套接字缓冲区

为了提高性能，通常增加套接字缓冲区的大小非常有利，因为它们不再只是单台机器的工作，而是作为您在常规机器连接上运行的所有 Docker 容器的工作。为此，有一些设置您可能应该设置，以确保套接字缓冲区不会努力跟上所有通过它们传递的流量。在撰写本书时，大多数这些默认缓冲区设置在机器启动时通常非常小（在我检查过的一些机器上为 200 KB），它们应该是动态缩放的，但您可以强制从一开始就使它们变得更大。

在 Ubuntu LTS 16.04 安装中，默认的缓冲区设置如下（尽管您的设置可能有所不同）：

```
net.core.optmem_max = 20480
net.core.rmem_default = 212992
net.core.rmem_max = 212992
net.core.wmem_default = 212992
net.core.wmem_max = 212992
net.ipv4.tcp_rmem = 4096 87380 6291456
net.ipv4.tcp_wmem = 4096 16384 4194304
```

我们将通过将以下内容添加到`/etc/sysctl.d/10-socket-buffers.conf`中，将这些值调整为一些合理的默认值，但请确保在您的环境中使用合理的值：

```
net.core.optmem_max = 40960
net.core.rmem_default = 16777216
net.core.rmem_max = 16777216
net.core.wmem_default = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 87380 16777216
```

通过增加这些值，我们的缓冲区变得更大，应该能够处理相当多的流量，并且具有更好的吞吐量，这是我们在集群环境中想要的。

# 临时端口

如果您不熟悉临时端口，它们是所有出站连接分配的端口号，如果未在连接上明确指定起始端口，那就是绝大多数端口。例如，如果您使用几乎每个客户端库进行任何类型的出站 HTTP 请求，您很可能会发现其中一个临时端口被分配为连接的返回通信端口。

要查看您的机器上一些示例临时端口的使用情况，您可以使用`netstat`：

```
$ netstat -an | grep ESTABLISHED
tcp        0      0 192.168.56.101:46496     <redacted>:443      ESTABLISHED
tcp        0      0 192.168.56.101:45512     <redacted>:443      ESTABLISHED
tcp        0      0 192.168.56.101:42014     <redacted>:443      ESTABLISHED
<snip>
tcp        0      0 192.168.56.101:45984     <redacted>:443      ESTABLISHED
tcp        0      0 192.168.56.101:56528     <redacted>:443      ESTABLISHED
```

当您开发具有大量出站连接的多个服务的系统时（在使用 Docker 服务时几乎是强制性的），您可能会注意到您被允许使用的端口数量有限，并且可能会发现这些端口可能与一些内部 Docker 服务使用的范围重叠，导致间歇性且经常令人讨厌的连接问题。为了解决这些问题，需要对临时端口范围进行更改。

由于这些也是内核设置，我们可以使用`sysctl`来查看我们当前的范围，就像我们在之前的几个示例中所做的那样：

```
$ sysctl net.ipv4.ip_local_port_range
net.ipv4.ip_local_port_range = 32768    60999
```

您可以看到我们的范围在端口分配的上半部分，但在该范围内可能开始监听的任何服务都可能遇到麻烦。我们可能需要的端口数量也可能超过 28,000 个。

您可能会好奇如何获取或设置此参数的`ipv6`设置，但幸运的是（至少目前是这样），这个相同的设置键用于`ipv4`和`ipv6`临时端口范围。在某个时候，这个设置名称可能会改变，但我认为至少还有几年的时间。

要更改此值，我们可以使用`sysctl -w`进行临时更改，或者使用`sysctl.d`进行永久更改：

```
$ # First the temporary change to get us up to 40000
$ # ports. For our services, we separately have to
$ # ensure none listen on any ports above 24999.
$ sudo sysctl -w net.ipv4.ip_local_port_range="25000 65000"
net.ipv4.ip_local_port_range = 25000 65000

$ # Sanity check
$ sysctl net.ipv4.ip_local_port_range
net.ipv4.ip_local_port_range = 25000    65000

$ # Now for the permanent change (requires restart)
$ echo "net.ipv4.ip_local_port_range = 25000 65000" | sudo tee /etc/sysctl.d/10-ephemeral-ports.conf
```

通过这个改变，我们有效地增加了我们可以支持的出站连接数量超过 30％，但我们也可以使用相同的设置来确保临时端口不会与其他运行中的服务发生冲突。

# Netfilter 调整

很遗憾，到目前为止我们看到的设置并不是唯一需要调整的东西，随着对服务器的网络连接增加，您可能还会在`dmesg`和/或内核日志中看到`nf_conntrack: table full`错误。对于不熟悉`netfilter`的人来说，它是一个跟踪所有**网络地址转换**（**NAT**）会话的内核模块，它将任何新连接添加到哈希表中，并在关闭连接并达到预定义的超时后清除它们，因此随着对单台机器的连接数量增加，您很可能会发现大多数相关设置都是默认的保守设置，需要进行调整（尽管您的发行版可能有所不同-请确保验证您的设置！）：

```
$ sysctl -a | grep nf_conntrack
net.netfilter.nf_conntrack_buckets = 65536
<snip>
net.netfilter.nf_conntrack_generic_timeout = 600
<snip>
net.netfilter.nf_conntrack_max = 262144
<snip>
net.netfilter.nf_conntrack_tcp_timeout_close = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_established = 432000
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 30
net.netfilter.nf_conntrack_tcp_timeout_max_retrans = 300
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 60
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 120
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_unacknowledged = 300
<snip>
```

其中有很多可以改变，但需要调整的错误通常是以下几种：

+   `net.netfilter.nf_conntrack_buckets`：控制连接的哈希表的大小。增加这个是明智的，尽管它可以用更激进的超时来替代。请注意，这不能使用常规的`sysctl.d`设置，而是需要使用内核模块参数进行设置。

+   `net.netfilter.nf_conntrack_max`：要保存的条目数。默认情况下，这是前一个条目值的四倍。

+   `net.netfilter.nf_conntrack_tcp_timeout_established`: 这将保持开放连接的映射长达五天之久(!)。通常情况下，必须减少这个时间以避免连接跟踪表溢出，但不要忘记它需要大于 TCP 的`keepalive`超时时间，否则会出现意外的连接中断。

要应用最后两个设置，您需要将以下内容添加到`/etc/sysctl.d/10-conntrack.conf`，并根据自己的基础架构配置调整值：

```
net.netfilter.nf_conntrack_tcp_timeout_established = 43200
net.netfilter.nf_conntrack_max = 524288
```

netfilter 是一个非常复杂的话题，在一个小节中涵盖不全，因此在更改这些数字之前，强烈建议阅读其影响和配置设置。要了解每个设置的情况，您可以访问[`www.kernel.org/doc/Documentation/networking/nf_conntrack-sysctl.txt`](https://www.kernel.org/doc/Documentation/networking/nf_conntrack-sysctl.txt)并阅读相关内容。

对于桶计数，您需要直接更改`nf_conntrack` `hashsize`内核模块参数：

```
echo '131072' | sudo tee /sys/module/nf_conntrack/parameters/hashsize
```

最后，为了确保在加载 netfilter 模块时遵循正确的顺序，以便这些值正确地持久化，您可能还需要将以下内容添加到`/etc/modules`的末尾：

```
nf_conntrack_ipv4
nf_conntrack_ipv6
```

如果一切都正确完成，下次重启应该会设置所有我们讨论过的 netfilter 设置。

# 多服务容器

多服务容器是一个特别棘手的话题，因为 Docker 的整个概念和推荐的用法是您只在容器中运行单进程服务。因此，有相当多的隐含压力不要涉及这个话题，因为开发人员很容易滥用并误用它，而不理解为什么强烈不建议这种做法。

然而，话虽如此，有时您需要在一个紧密的逻辑分组中运行多个进程，而多容器解决方案可能没有意义，或者会过于笨拙，这就是为什么这个话题仍然很重要的原因。话虽如此，我再次强调，您应该将这种类型的服务共存作为最后的手段。

在我们写下一行代码之前，我们必须讨论一个架构问题，即在同一个容器内运行多个进程的问题，这被称为`PID 1`问题。这个问题的关键在于 Docker 容器在一个隔离的环境中运行，它们无法从主机的`init`进程中获得帮助来清理孤儿子进程。考虑一个例子进程`父进程`，它是一个基本的可执行文件，启动另一个进程称为`子进程`，但在某个时刻，如果相关的`父进程`退出或被杀死，你将会留下在容器中游荡的僵尸`子进程`，因为`父进程`已经消失，容器沙盒中没有其他孤儿收割进程在运行。如果容器退出，那么僵尸进程将被清理，因为它们都被包裹在一个命名空间中，但对于长时间运行的任务来说，这可能会对在单个镜像内运行多个进程造成严重问题。

这里的术语可能会令人困惑，但简单来说，每个进程在退出后都应该被从进程表中移除（也称为收割），要么是由父进程，要么是由层次结构中的其他指定进程（通常是`init`）来接管它以完成最终的清理。在这种情况下，没有运行父进程的进程被称为孤儿进程。

有些工具有能力收割这些僵尸进程（比如 Bash 和其他几个 shell），但即使它们也不是我们容器的良好 init 进程，因为它们不会将信号（如 SIGKILL、SIGINT 等）传递给子进程，因此停止容器或在终端中按下 Ctrl + C 等操作是无效的，不会终止容器。如果你真的想在容器内运行多个进程，你的启动进程必须进行孤儿收割和信号传递给子进程。由于我们不想从容器中使用完整的 init 系统，比如`systemd`，这里有几种替代方案，但在最近的 Docker 版本中，我们现在有`--init`标志，它可以使用真正的 init 运行器进程来运行我们的容器。

让我们看看这个过程，并尝试退出一个以`bash`为起始进程的程序：

```
$ # Let's try to run 'sleep' and exit with <Ctrl>-C
$ docker run -it \
 ubuntu \
 bash -c 'sleep 5000'
^C^C^C^C^C^C^C^C^C^C
<Ctrl-C not working>

$ # On second terminal
$ docker ps
CONTAINER ID IMAGE  COMMAND                CREATED            STATUS 
c7b69001271d ubuntu "bash -c 'sleep 5000'" About a minute ago Up About a minute

$ # Can we stop it?
$ docker stop c7b69001271d
<nothing happening>
^C

$ # Last resort - kill the container!
$ docker kill c7b69001271d
c7b69001271d
```

这次，我们将使用`--init`标志运行我们的容器：

```
$ docker run -it \
 --init \
 ubuntu \
 bash -c 'sleep 5000'
^C

$ # <Ctrl>-C worked just fine!
```

正如你所看到的，`--init`能够接收我们的信号并将其传递给所有正在监听的子进程，并且它作为一个孤儿进程收割者运行良好，尽管后者在基本容器中真的很难展示出来。有了这个标志及其功能，你现在应该能够使用诸如 Bash 之类的 shell 运行多个进程，或者升级到一个完整的进程管理工具，比如`supervisord`（[`supervisord.org/`](http://supervisord.org/)），而不会出现任何问题。

# 零停机部署

在每次集群部署时，您都会在某个时候需要考虑代码重新部署，同时最大程度地减少对用户的影响。对于小规模部署，有可能您会有一个维护期，在此期间您关闭所有内容，重建新的镜像，并重新启动服务，但这种部署方式实际上并不适合中等和大型集群的管理，因为您希望最小化维护集群所需的任何直接工作。事实上，即使对于小集群，以无缝的方式处理代码和配置升级对于提高生产率来说也是非常宝贵的。

# 滚动服务重启

如果新的服务代码没有改变它与其他服务交互的基本方式（输入和输出），通常唯一需要的就是重建（或替换）容器镜像，然后将其放入 Docker 注册表，然后以有序和交错的方式重新启动服务。通过交错重启，始终至少有一个任务可以处理服务请求，并且从外部观点来看，这种转换应该是完全无缝的。大多数编排工具会在您更改或更新服务的任何设置时自动为您执行此操作，但由于它们非常特定于实现，我们将专注于 Docker Swarm 作为我们的示例：

```
$ # Create a new swarm
$ docker swarm init
Swarm initialized: current node (j4p08hdfou1tyrdqj3eclnfb6) is now a manager.
<snip>

$ # Create a service based on mainline NGINX and update-delay
$ # of 15 seconds
$ docker service create \
 --detach=true \
 --replicas 4 \
 --name nginx_update \
 --update-delay 15s \
 nginx:mainline
s9f44kn9a4g6sf3ve449fychv

$ # Let's see what we have
$ docker service ps nginx_update
ID            NAME            IMAGE           DESIRED STATE  CURRENT STATE
rbvv37cg85ms  nginx_update.1  nginx:mainline  Running        Running 56 seconds ago
y4l76ld41olf  nginx_update.2  nginx:mainline  Running        Running 56 seconds ago
gza13g9ar7jx  nginx_update.3  nginx:mainline  Running        Running 56 seconds ago
z7dhy6zu4jt5  nginx_update.4  nginx:mainline  Running        Running 56 seconds ago

$ # Update our service to use the stable NGINX branch
$ docker service update \
 --detach=true \
 --image nginx:stable \
 nginx_update
nginx_update

$ # After a minute, we can now see the new service status
$ docker service ps nginx_update
ID            NAME               IMAGE           DESIRED STATE  CURRENT STATE
qa7evkjvdml5  nginx_update.1     nginx:stable    Running        Running about a minute ago
rbvv37cg85ms  \_ nginx_update.1  nginx:mainline  Shutdown       Shutdown about a minute ago
qbg0hsd4nxyz  nginx_update.2     nginx:stable    Running        Running about a minute ago
y4l76ld41olf  \_ nginx_update.2  nginx:mainline  Shutdown       Shutdown about a minute ago
nj5gcf541fgj  nginx_update.3     nginx:stable    Running        Running 30 seconds ago
gza13g9ar7jx  \_ nginx_update.3  nginx:mainline  Shutdown       Shutdown 31 seconds ago
433461xm4roq  nginx_update.4     nginx:stable    Running        Running 47 seconds ago
z7dhy6zu4jt5  \_ nginx_update.4  nginx:mainline  Shutdown       Shutdown 48 seconds ago

$ # All our services now are using the new image
$ # and were started staggered!

$ # Clean up
$ docker service rm nginx_update 
nginx_update 
$ docker swarm leave --force 
Node left the swarm.
```

正如你所看到的，应该很容易做到在没有任何停机时间的情况下进行自己的代码更改！

如果你想要能够一次重启多个任务而不是一个，Docker Swarm 也有一个`--update-parallelism <count>`标志，可以设置在一个服务上。使用这个标志时，仍然会观察`--update-delay`，但是不是单个任务被重启，而是以`<count>`大小的批次进行。

# 蓝绿部署

滚动重启很好，但有时需要应用的更改是在主机上，需要对集群中的每个 Docker Engine 节点进行更改，例如，如果需要升级到更新的编排版本或升级操作系统版本。在这些情况下，通常接受的做法是使用一种称为**蓝绿部署**的方法来完成，而不需要大量的支持团队。它通过在当前运行的集群旁边部署一个次要集群开始，可能与相同的数据存储后端相关联，然后在最合适的时间将入口路由切换到新集群。一旦原始集群上的所有处理都完成后，它将被删除，新集群将成为主要处理组。如果操作正确，用户的影响应该是不可察觉的，并且整个基础设施在此过程中已经发生了变化。

该过程始于次要集群的创建。在那时，除了测试新集群是否按预期运行外，没有实质性的变化：

（图片）

次要集群运行后，路由器交换端点，处理继续在新集群上进行：

（图片）

交换完成后，所有处理完成后，原始集群被废弃（或作为紧急备份留下）：

（图片）

但是在完整集群上应用这种部署模式并不是它的唯一用途——在某些情况下，可以在同一集群内的服务级别上使用相同的模式来替换更高版本的组件，但是有一个更好的系统可以做到这一点，我们接下来会介绍。

# 蓝绿部署

在代码部署中，情况变得有些棘手，因为在输入或输出端或数据库架构上更改 API 可能会对具有交错代码版本的集群造成严重破坏。为了解决这个问题，有一种修改过的蓝绿部署模式称为**蓝绿松石绿部署**，其中尝试使代码与所有运行版本兼容，直到部署新代码后，然后通过删除兼容代码再次更新服务。

这里的过程非常简单：

1.  使用 API 版本`x`的服务以滚动方式替换为支持 API 版本`x`和 API 版本`(x+1)`的新版本服务。这从用户的角度提供了零停机时间，但创建了一个具有更新的 API 支持的新服务。

1.  在一切更新完成后，具有旧 API 版本`x`的服务将从代码库中删除。

1.  对服务进行另一次滚动重启，以删除废弃 API 的痕迹，只留下 API 版本`(x+1)`的支持。

当您使用的服务需要持续可用时，这种方法非常有价值，在许多情况下，您可以轻松地将 API 版本替换为消息队列格式，如果您的集群基于队列。过渡是平稳的，但与一次硬交换相比，需要两次修改服务，但这是一个不错的权衡。当使用的服务涉及可能需要迁移的数据库时，这种方法也非常有价值，因此当其他方法不够好时，您应该使用这种方法。

# 摘要

在本章中，我们涵盖了各种工具和技术，这些工具和技术将在您将基础架构规模扩大到简单原型之外时需要。到目前为止，我们应该已经学会了如何限制服务访问主机资源，轻松处理最常见的问题，运行多个服务在一个容器中，并处理零停机部署和配置更改。

在下一章中，我们将花时间部署我们自己的**平台即服务**（PAAS）的迷你版本，使用我们迄今为止学到的许多知识。
