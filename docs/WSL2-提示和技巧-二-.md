# WSL2 提示和技巧（二）

> 原文：[`zh.annas-archive.org/md5/5EBC4B193F90421D3484B13463D11C33`](https://zh.annas-archive.org/md5/5EBC4B193F90421D3484B13463D11C33)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 WSL 发行版

在*第二章*中，*安装和配置 Windows 子系统 Linux*，在*介绍 wsl 命令*部分，我们看到了如何使用`wsl`命令列出我们安装的**发行版**（**distros**），在其中运行命令，并根据需要终止它们。

在本章中，我们将重新讨论发行版，这次从发行版管理的角度来看。特别是，我们将看看如何使用`export`和`import`命令备份发行版或将其复制到另一台机器。我们还将看看如何快速创建一个基于 Docker 容器映像的新发行版，以便您可以轻松创建自己的发行版，并安装任何依赖项。

在本章中，我们将介绍以下主要内容：

+   导出和导入 WSL 发行版

+   创建和运行自定义发行版

我们将从介绍如何导出和导入 WSL 发行版开始本章。

# 导出和导入 WSL 发行版

如果您花费了时间设置 WSL 发行版，您可能希望能够将其复制到另一台机器上。这可能是因为您正在更换或重新安装计算机，或者您拥有多台计算机，希望将配置好的发行版复制到第二台计算机上，而不是从头开始设置发行版。在本节中，我们将介绍如何将发行版导出为可以复制到另一台机器并导入的存档文件。

让我们首先准备要导出的发行版。

## 准备导出

在导出发行版之前，我们要确保发行版的默认用户在发行版内的`/etc/wsl.conf`文件中设置正确（您可以在*第二章*中的*安装和配置 Windows 子系统 Linux*，*介绍 wsl.conf 和.wslconfig*部分了解更多关于`wsl.conf`的信息）。通过这样做，我们可以确保在导入发行版后，WSL 仍然使用正确的默认用户。

在 WSL 发行版中打开终端并运行`cat /etc/wsl.conf`以检查文件的内容：

```
$ cat /etc/wsl.conf
[network]
generateHosts = true
generateResolvConf = true
[user]
default=stuart
```

在此输出的末尾，您可以看到带有`default=stuart`条目的`[user]`部分。如果您没有默认用户条目（或者没有`wsl.conf`文件），那么您可以使用您喜欢的编辑器确保有一个类似于此的条目（带有正确的用户名）。或者，您可以运行以下命令添加一个用户（假设您的`wsl.conf`没有`[user]`部分）：

```
sudo bash -c "echo -e '\n[user]\ndefault=$(whoami)' >> /etc/wsl.conf"
```

此命令使用`echo`输出带有默认设置为当前用户的`[user]`部分。它嵌入了调用`whoami`获取当前用户名的结果。整个命令被包装并使用`sudo`执行，以确保具有写入文件所需的权限。

准备工作完成后，让我们看看如何导出发行版。

## 执行导出

要导出发行版，我们将使用`wsl`命令将发行版的内容导出到磁盘上的文件中。为此，我们运行`wsl --export`：

```
wsl --export Ubuntu-18.04 c:\temp\Ubuntu-18.04.tar
```

正如您所看到的，我们指定了要导出的发行版的名称（`Ubuntu-18.04`），然后是我们要保存导出文件的路径（`c:\temp\Ubuntu-18.04.tar`）。导出过程将根据发行版的大小和其中的内容量而需要一些时间来完成。

在导出过程中，发行版无法使用，如使用`wsl --list`命令（在单独的终端实例中执行）所示：

```
PS C:\> wsl --list --verbose
  NAME                   STATE           VERSION
* Ubuntu-20.04           Running         2
  Legacy                 Stopped         1
  Ubuntu-18.04           Converting      2
PS C:\>
```

在此输出中，您可以看到`Ubuntu-18.04`发行版的状态显示为`Converting`。一旦导出命令完成，该发行版将处于`Stopped`状态。

导出的文件是一个以**TAR**格式（最初是**Tape Archive**的缩写）创建的存档文件，这在 Linux 中很常见。如果您打开 TAR 文件（例如，在诸如[`www.7-zip.org/`](https://www.7-zip.org/)的应用程序中），您可以看到其中的内容：

![图 8.1 - 展示在 7-zip 中打开的导出的 TAR 的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/B16412_Figure_8.1.jpg)

图 8.1 - 展示在 7-zip 中打开的导出的 TAR 的屏幕截图

在此屏幕截图中，您可以看到导出的 TAR 文件包含了一个 Linux 系统的熟悉文件夹。您可以深入到诸如 `/home/stuart` 的文件夹中，并导出单个文件（如果您希望这样做）。

现在我们有了一个导出的发行版文件，让我们看看如何导入它。

## 执行导入

一旦您有了发行版的导出文件，您可以将其复制到新机器（假设您正在传输发行版），或者如果您使用导出/导入来创建发行版的副本，则可以将其保留在同一位置。

要执行导入，我们将使用以下 `wsl` 命令：

```
wsl --import Ubuntu-18.04-Copy C:\wsl-distros\Ubuntu-18.04-Copy C:\temp\Ubuntu-18.04.tar
```

正如您所看到的，这次我们使用了 `--import` 开关。之后，我们传递以下三个参数：

+   `Ubuntu-18.04-Copy`：这是将由导入创建的新发行版的名称。

+   `C:\wsl-distros\Ubuntu-18.04-Copy`：这是新发行版的状态将存储在磁盘上的路径。通过商店安装的发行版将安装在 `$env:LOCALAPPDATA\Packages` 下的文件夹中，如果您希望将导入的发行版保存在类似位置的路径下，您可以使用此路径。

+   `C:\temp\Ubuntu-18.04.tar`：要导入的已导出发行版的 TAR 文件的路径。

与导出一样，如果内容很多，导入过程可能需要一些时间。我们可以通过在另一个终端实例中运行 `wsl` 来查看状态：

```
PS C:\ > wsl --list --verbose
  NAME                   STATE           VERSION
* Ubuntu-20.04           Running         2
  Legacy                 Stopped         1
  Ubuntu-18.04-Copy      Installing      2
  Ubuntu-18.04           Stopped         2
PS C:\Users\stuar>
```

在此输出中，我们可以看到新的发行版（`Ubuntu-18.04-Copy`）在导入过程中显示为 `Installing` 状态。一旦 `import` 命令完成，新的发行版就可以使用了。

正如您在这里看到的，通过将发行版导出为可以导入的 TAR 文件，您可以在您的计算机上创建发行版的副本，例如，测试一些其他应用程序而不影响原始发行版。通过在计算机之间复制 TAR 文件，它还可以让您复制已配置的发行版以便在计算机之间重用它们。

接下来，我们将看看如何创建自己的发行版。

# 创建和运行自定义发行版

如果您在多个项目中工作，每个项目都有自己的工具集，并且您希望保持依赖关系的分离，那么为每个项目运行一个发行版可能是有吸引力的。我们刚刚看到的导出和导入发行版的技术可以通过复制起始发行版来实现这一点。

在本节中，我们将介绍使用 Docker 镜像的另一种方法。Docker Hub 上发布了大量的镜像，包括安装了各种开发工具集的镜像。正如我们将在本节中看到的，这可以是一种快速安装发行版以使用新工具集的方法。在*第十章*中，*Visual Studio Code 和容器*，我们将看到另一种方法，直接使用容器来封装您的开发依赖项。

在开始之前，值得注意的是，还有另一种构建用于 WSL 的自定义发行版的方法，但这是一个更复杂的过程，并且不适用于本节的场景。这也是发布 Linux 发行版到商店的途径 - 详细信息可以在[`docs.microsoft.com/en-us/windows/wsl/build-custom-distro`](https://docs.microsoft.com/en-us/windows/wsl/build-custom-distro)找到。

在本节中，我们将介绍如何使用容器设置一个准备好与 .NET Core 一起工作的发行版（但是这个过程适用于任何您可以找到容器镜像的技术栈）。我们将使用 Docker Hub 找到我们想要用作新 WSL 发行版基础的镜像，然后配置一个正在运行的容器，以便它能够与 WSL 无缝配合。一旦我们设置好容器，我们将导出它为一个可以像前一节中所见那样导入的 TAR 文件。

让我们开始找到我们想要使用的镜像。

## 查找和拉取容器镜像

第一步是找到我们想要用作起点的容器。在 Docker Hub 上搜索`dotnet`后（[`hub.docker.com/`](https://hub.docker.com/)），我们可以向下滚动以找到来自 Microsoft 的镜像，这将引导我们到这个页面（[`hub.docker.com/_/microsoft-dotnet-core`](https://hub.docker.com/_/microsoft-dotnet-core)）：

![图 8.2 - Docker Hub 上.NET 镜像页面的截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/B16412_Figure_8.2.jpg)

图 8.2 - Docker Hub 上.NET 镜像页面的截图

正如您在这个截图中所看到的，有许多可用的.NET 镜像。在本章中，我们将使用.NET 5.0 镜像，特别是 SDK 镜像，因为我们希望能够测试构建应用程序（而不仅仅是运行为运行时镜像设计的应用程序）。

通过点击`dotnet/sdk`页面，我们可以找到我们需要使用的镜像标签来拉取和运行镜像：

![图 8.3 - Docker Hub 上显示.NET 5.0 SDK 镜像标签的截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/B16412_Figure_8.3.jpg)

图 8.3 - Docker Hub 上显示.NET 5.0 SDK 镜像标签的截图

正如这个截图所示，我们可以运行`docker pull mcr.microsoft.com/dotnet/sdk:5.0`将镜像拉取到我们的本地机器上。

现在我们已经找到了要用作新发行版起点的镜像，接下来有几个步骤来准备它以便与 WSL 一起使用。让我们看看这些步骤是什么。

## 配置一个准备用于 WSL 的容器

在我们可以导出刚从 Docker Hub 拉取的镜像之前，我们需要进行一些调整，以使其与 WSL 完全兼容：

1.  首先，我们将从镜像创建一个正在运行的容器：

```
dotnet to make it easier to refer to it later. We also passed the -it switches to start the container with interactive access – note the final line in the previous output showing that we're at a shell prompt inside the container.
```

1.  首先要设置的是 WSL 要使用的用户：

```
useradd command to create a new user called stuart (but feel free to pick a different name!) and the -m switch ensures that the user home directory is created. After that, we use the passwd command to set a password for the user.
```

1.  接下来，我们将添加`/etc/wsl.conf`文件以告诉 WSL 使用我们刚创建的用户：

```
echo command to set the file content, but you can use your favorite terminal text editor if you prefer. After writing the file, we dump it out to show the contents – be sure to set the value of the default property to match the user you created here.
```

在这个阶段，我们可以进行额外的配置（我们将在本章后面的“进一步操作”部分中看到一些示例），但是现在基本的准备工作已经完成，所以让我们将容器转换为 WSL 发行版。

## 将容器转换为 WSL 发行版

在本章的第一节中，我们看到了如何将 WSL 发行版导出为 TAR 文件，然后将该 TAR 文件作为新的发行版导入（在同一台或不同的机器上）。

幸运的是，Docker 提供了一种将容器导出为与 WSL 使用的格式兼容的 TAR 文件的方法。在本节中，我们将采用刚刚配置的容器，并使用导出/导入过程将其转换为 WSL 发行版。

在导出之前，让我们退出容器：

```
root@62bdd6b50070:/# exit
exit
PS C:\> docker ps -a
CONTAINER ID        IMAGE                              COMMAND                  CREATED             STATUS                     PORTS               NAMES
62bdd6b50070        mcr.microsoft.com/dotnet/sdk:5.0   "bash"                   52 minutes ago      Exited (0) 7 seconds ago                        dotnet
```

这个输出显示了运行`exit`命令以退出容器中的`bash`实例。这会导致容器进程退出，容器不再运行。通过运行`docker ps -a`，我们可以看到所有容器的列表（包括已停止的容器），并且我们可以看到我们一直在使用的容器被列出。

接下来，我们可以将 Docker 容器导出为一个 TAR 文件：

```
docker export -o c:\temp\dotnet.tar dotnet
```

在这里，我们使用`docker export`命令。`-o`开关提供输出 TAR 文件的路径，最后一个参数是我们要导出的容器的名称（`dotnet`）。

一旦这个命令完成（可能需要一些时间），我们就可以使用`wsl`命令导入准备好的 TAR 文件：

```
wsl --import dotnet5 C:\wsl-distros\dotnet5 C:\temp\dotnet.tar --version 2
```

`import`命令与前面的部分相同。第一个参数是我们要创建的发行版的名称，`dotnet5`；第二个参数指定 WSL 应该存储发行版的位置；最后，我们给出要导入的 TAR 文件的路径。

完成后，我们创建了一个新的 WSL 发行版，准备运行它。

## 运行新的发行版

现在我们已经创建了一个新的发行版，我们可以进行测试。让我们在发行版中启动一个新的`bash`实例，并检查我们正在以哪个用户身份运行：

```
PS C:\> wsl -d dotnet5 bash
stuart@wfhome:/mnt/c$ whoami
stuart
stuart@wfhome:/mnt/c$ 
```

在这里，我们在刚刚创建的`dotnet5`发行版中启动`bash`，并运行`whoami`。这表明我们正在以我们在导入发行版之前在容器中创建和配置的`stuart`用户身份运行。

现在我们可以测试运行`dotnet`：

1.  首先，让我们用`dotnet new`创建一个新的 Web 应用程序：

```
stuart@wfhome:~$ dotnet new webapp --name new-web-app
The template "ASP.NET Core Web App" was created successfully.
This template contains technologies from parties other than Microsoft, see https://aka.ms/aspnetcore/5.0-third-party-notices for details.
Processing post-creation actions...
Running 'dotnet restore' on new-web-app/new-web-app.csproj...
  Determining projects to restore...
  Restored /home/stuart/new-web-app/new-web-app.csproj (in 297 ms).
Restore succeeded.
```

1.  接下来，我们可以切换到新的 Web 应用程序目录，并使用`dotnet run`运行它：

```
stuart@wfhome:~$ cd new-web-app/
stuart@wfhome:~/new-web-app$ dotnet run
warn: Microsoft.AspNetCore.DataProtection.KeyManagement.XmlKeyManager[35]
      No XML encryptor configured. Key {d4a5da2e-44d5-4bf7-b8c9-ae871b0cdc42} may be persisted to storage in unencrypted form.
info: Microsoft.Hosting.Lifetime[0]
      Now listening on: https://localhost:5001
info: Microsoft.Hosting.Lifetime[0]
      Now listening on: http://localhost:5000
info: Microsoft.Hosting.Lifetime[0]
      Application started. Press Ctrl+C to shut down.
info: Microsoft.Hosting.Lifetime[0]
      Hosting environment: Development
info: Microsoft.Hosting.Lifetime[0]
      Content root path: /home/stuart/new-web-app
^Cinfo: Microsoft.Hosting.Lifetime[0]
      Application is shutting down...
```

正如您所看到的，这种方法为我们提供了一种快速创建新的、独立的 WSL 发行版的好方法，这可以用来在项目之间拆分不同的依赖关系。这种方法还可以用来创建临时发行版，以尝试预览而不在主要发行版中安装它们。在这种情况下，您可以使用`wsl --unregister dotnet5`来删除发行版，并释放磁盘空间。

我们在这里使用的过程要求我们交互地执行一些步骤，在许多情况下这是可以接受的。如果您发现自己重复执行这些步骤，您可能希望将它们更加自动化，我们将在下一步中看看如何做到这一点。

## 进一步的步骤

到目前为止，我们已经看到了如何使用 Docker 交互式地设置一个可以导出为 TAR 文件并作为 WSL 发行版导入的容器。在本节中，我们将看看如何自动化这个过程，并作为自动化的一部分，我们将添加一些额外的步骤来完善之前执行的镜像准备工作。

容器配置自动化的基础是我们在*第七章*中看到的`Dockerfile`，即在*在 WSL 中使用容器*一节中的*介绍 Dockerfile*部分。我们可以使用`Dockerfile`来构建镜像，然后我们可以按照之前的步骤运行一个容器从镜像中导出文件系统到一个可以作为 WSL 发行版导入的 TAR 文件中。

让我们从`Dockerfile`开始。

### 创建 Dockerfile

`docker build`命令允许我们传递一个`Dockerfile`来自动化构建容器镜像的步骤。这里显示了一个`Dockerfile`的起点：

```
FROM mcr.microsoft.com/dotnet/sdk:5.0
ARG USERNAME
ARG PASSWORD
RUN useradd -m ${USERNAME}
RUN bash -c 'echo -e "${PASSWORD}\n${PASSWORD}\n" | passwd ${USERNAME}'
RUN bash -c 'echo -e "[user]\ndefault=${USERNAME}" > /etc/wsl.conf'
RUN usermod -aG sudo ${USERNAME}
RUN apt-get update && apt-get -y install sudo 
```

在这个`Dockerfile`中，我们在`FROM`步骤中指定了起始镜像（之前使用的`dotnet/sdk`镜像），然后使用了一些`ARG`语句来允许传递`USERNAME`和`PASSWORD`。之后，我们使用`RUN`运行了一系列命令来配置镜像。通常，在一个`Dockerfile`中，您会看到这些命令被连接为一个单独的`RUN`步骤，以帮助减少层数和大小，但在这里，我们只是要导出完整的文件系统，所以无所谓。让我们看一下这些命令：

+   我们有`useradd`，之前我们用它来创建用户，这里我们使用它和`USERNAME`参数值。

+   `passwd`命令要求用户输入密码两次，所以我们使用`echo`在两次密码之间输出一个换行，并将其传递给`passwd`。我们调用`bash`来运行这个命令，这样我们就可以使用`\n`来转义换行符。

+   我们再次使用`echo`来将`/etc/wsl.conf`的内容设置为配置 WSL 的默认用户。

+   我们调用`usermod`将用户添加到`sudo`ers 组，以允许用户运行`sudo`。

+   然后，我们使用`apt-get`来安装`sudo`实用程序。

正如您所看到的，这个列表涵盖了我们之前手动运行的步骤以及一些其他步骤，以设置`sudo`以使环境感觉更加自然。您可以在这里添加任何其他步骤，并且这个`Dockerfile`可以通过更改`FROM`镜像来重用于其他基于 Debian 的镜像。

接下来，我们可以使用 Docker 从`Dockerfile`构建一个镜像。

### 创建 TAR 文件

现在我们有了一个`Dockerfile`，我们需要调用 Docker 来构建镜像并创建 TAR 文件。我们可以使用以下命令来完成这个过程：

```
docker build -t dotnet-test -f Dockerfile --build-arg USERNAME=stuart --build-arg PASSWORD=ticONUDavE .
docker run --name dotnet-test-instance dotnet-test
docker export -o c:\temp\chapter-08-dotnet.tar dotnet-test-instance
docker rm dotnet-test-instance
```

这组命令执行了从`Dockerfile`创建 TAR 文件所需的步骤：

+   运行`docker build`，指定要创建的镜像名称（`dotnet-test`），输入的`Dockerfile`，以及我们定义的每个`ARG`的值。在这里，您可以设置要使用的用户名和密码。

+   使用`docker run`从镜像创建一个容器。我们必须这样做才能导出容器文件系统。Docker 确实有一个`save`命令，但它保存的是包含层的完整镜像，而这不是我们需要导入到 WSL 的格式。

+   运行`docker export`将容器文件系统导出为一个 TAR 文件。

+   使用`docker rm`删除容器以释放空间并使重新运行命令变得容易。

此时，我们已经有了 TAR 文件，我们可以像在前一节中看到的那样运行`wsl --import`来创建我们的新 WSL 发行版：

```
wsl --import chapter-08-dotnet c:\wsl-distros\chapter-08-dotnet c:\temp\chapter-08-dotnet.tar
```

这将创建一个名为`chapter-08-dotnet`的发行版，其中包含我们在`Dockerfile`中应用的指定用户和配置。

有了这些可脚本化的命令，创建新的发行版变得很容易。您可以在`Dockerfile`中添加步骤来添加其他应用程序或配置。例如，如果您打算在该发行版中使用 Azure，您可能希望通过将以下行添加到您的`Dockerfile`来方便地安装 Azure CLI：

```
RUN  curl -sL https://aka.ms/InstallAzureCLIDeb | bash
```

这个`RUN`命令是基于 Azure CLI 文档中的安装说明（[`docs.microsoft.com/en-us/cli/azure/install-azure-cli-apt?view=azure-cli-latest`](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-apt?view=azure-cli-latest)）。

通过这种方式，您可以轻松地脚本化创建根据您需求配置的新 WSL 发行版。无论您计划长时间保留它们还是将它们视为临时的可丢弃环境，这都是您工具包中的强大工具。

# 总结

在本章中，您已经了解了如何使用 WSL 的`export`和`import`命令。这些命令允许您将发行版复制到其他计算机，或在重新安装计算机时备份和恢复发行版。它们还提供了一种克隆发行版的方法，如果您想要进行实验或在副本中工作而不影响原始发行版。

您还看到了如何使用*容器*构建新的发行版。这提供了一种有效的方式来设置新的发行版，以便在其中工作，或者快速测试应用程序而不影响原始发行版。如果您在项目之间具有不同的技术堆栈，并且希望在它们的依赖之间有一些隔离，那么这也可以是设置每个项目发行版的好方法。能够以脚本方式创建这些发行版有助于提高生产力，如果您发现自己使用这种多发行版方法。

随着我们通过使用 Dockerfile 脚本化创建这些环境的进展，我们越来越接近与容器一起工作。我们将在*第十章*中探索如何继续这个旅程，并直接使用容器进行开发工作，*Visual Studio Code 和容器*。

在此之前，下一章将介绍 Visual Studio Code，这是一款功能强大且免费的微软编辑器，并探索它如何允许我们在 WSL 中处理源代码。


# 第三部分：使用 Windows 子系统进行 Linux 开发

本节首先探索了 Visual Studio Code 在 WSL 发行版中为您处理代码提供的强大功能。您还将了解到 Visual Studio Code 如何允许您在 WSL 中使用容器构建隔离且易于共享的容器化开发环境。最后，我们将介绍一些在命令行实用程序中处理 JSON 的技巧以及一些 Azure 和 Kubernetes 命令行工具的技巧。

本节包括以下章节：

*第九章*，*Visual Studio Code 和 WSL*

*第十章*，*Visual Studio Code 和容器*

*第十一章*，*使用命令行工具的生产力技巧*


# 第九章：Visual Studio Code 和 WSL

到目前为止，本书的重点一直是 WSL 和直接使用 WSL 进行工作。在本章中，我们将提升一个层次，开始探讨在开发应用程序时如何在 WSL 之上工作。特别是在本章中，我们将探索微软提供的免费编辑器 Visual Studio Code。

我们已经看到 WSL 的互操作性允许我们从 Windows 访问 WSL 分发中的文件。Visual Studio Code 允许我们更深入地进行操作，通过在 Windows 中连接到运行在 WSL 分发中的支持编辑器服务，实现图形化编辑体验。通过这种方式，Visual Studio Code 为我们提供了一些能力，例如在 WSL 中运行的 Linux 应用程序的图形化调试体验。这使我们能够在 Visual Studio Code 中保持丰富的基于 Windows 的编辑体验的同时，与 WSL 中的工具和依赖项一起工作。

在本章中，我们将介绍以下主要内容：

+   介绍 Visual Studio Code

+   介绍 Visual Studio Code Remote

+   使用 Remote-WSL 的工作提示

我们将从介绍 Visual Studio Code 并安装它开始本章。

# 介绍 Visual Studio Code

**Visual Studio Code**是微软提供的一个免费、跨平台、开源的代码编辑器。它默认支持 JavaScript（和 TypeScript）应用程序，但可以通过扩展支持各种语言（包括 C++、Java、PHP、Python、Go、C#和 SQL）。让我们开始安装 Visual Studio Code。

要安装 Visual Studio Code，请访问[`code.visualstudio.com/`](https://code.visualstudio.com/)，点击下载链接，并在下载完成后运行安装程序。安装过程相当简单，但如果你想要更多详细信息（包括如何安装 Insiders 版本，提供每夜构建），请参阅[`code.visualstudio.com/docs/setup/setup-overview`](https://code.visualstudio.com/docs/setup/setup-overview)。

安装完成后，启动 Visual Studio Code 将呈现如下窗口：

![图 9.1 - Visual Studio Code 的截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.1_B16412.jpg)

图 9.1 - Visual Studio Code 的截图

在这个截图中，你可以看到 Visual Studio Code 中的**欢迎**页面。该页面提供了一些常见操作的链接（如打开文件夹），最近打开的文件夹（在首次安装时没有这些），以及各种有用的帮助页面。

总的来说，使用 Visual Studio Code 的基本用法可能会让人感到熟悉，与其他图形化编辑器类似。文档中有一些很好的入门视频（[`code.visualstudio.com/docs/getstarted/introvideos`](https://code.visualstudio.com/docs/getstarted/introvideos)）以及书面的技巧和技巧（[`code.visualstudio.com/docs/getstarted/tips-and-tricks`](https://code.visualstudio.com/docs/getstarted/tips-and-tricks)）。这些链接提供了许多有用的技巧，可以帮助你充分利用 Visual Studio Code，并推荐提高你的工作效率。

有多种选项可以打开一个文件夹开始工作：

+   在**欢迎**页面上使用**打开文件夹...**链接，如*图 9.1*所示。

+   在**文件**菜单中使用**打开文件夹...**选项。

+   在命令面板中使用**文件：打开文件夹...**选项。

这里的最后一个选项，使用命令面板，是一个强大的选项，因为它提供了在 Visual Studio Code 中快速搜索任何命令的方法。你可以通过按下*Ctrl* + *Shift* + *P*来访问命令面板：

![图 9.2 - 显示命令面板的截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.2_B16412.jpg)

图 9.2 - 显示命令面板的截图

此截图显示了命令面板打开的情况。命令面板提供对 Visual Studio Code 中所有命令（包括已安装扩展的命令）的访问。在命令面板中输入时，操作列表会被过滤。在此截图中，您可以看到我已经过滤了“文件打开”，这样可以快速访问“文件：打开文件夹…”操作。值得注意的是，命令面板还显示了命令的键盘快捷键，为学习常用命令的快捷方式提供了一种简单的方法。

如前所述，Visual Studio Code 有各种各样的扩展，可以在 https://marketplace.visualstudio.com/vscode 上浏览，或者您可以从命令面板中选择**Extensions: Install Extensions**来直接在 Visual Studio Code 中浏览和安装。扩展可以为 Visual Studio Code 添加功能，包括支持新的语言，提供新的编辑器主题或添加新的功能。在本章的示例中，我们将使用一个 Python 应用程序，但这些原则也适用于其他语言。要了解如何添加语言支持的更多信息，请参阅[`code.visualstudio.com/docs/languages/overview`](https://code.visualstudio.com/docs/languages/overview)。

在我们开始查看示例应用程序之前，让我们先看一下一个为 Visual Studio Code 添加了丰富的 WSL 支持的扩展。

# 介绍 Visual Studio Code Remote

从 WSL 发行版的文件系统中处理文件的一种方法是使用 WSL 提供的`\\wsl$`共享（如*第四章*中所讨论的*Windows 与 Linux 的互操作性*中的*从 Windows 访问 Linux 文件*部分）。例如，我可以从`\\wsl$\Ubuntu-20.04\home\stuart\wsl-book`中的我的主目录访问`wsl-book`文件夹。然而，尽管这样可以工作，但它会产生 Windows 到 Linux 文件互操作的成本，并且不能为我提供一个集成的环境。

在 Windows 上，如果我们安装了 Python 以及 Visual Studio Code 的 Python 扩展，那么我们可以获得一个集成的体验来运行和调试我们的代码。如果我们通过`\\wsl$`共享打开代码，那么 Visual Studio Code 仍然会给我们提供 Windows 体验，而不是使用 WSL 中 Python 及其依赖和工具的安装。然而，通过 Microsoft 的**Remote-WSL 扩展**，我们可以解决这个问题！

通过 Remote Development 扩展，Visual Studio Code 现在将体验分为 Visual Studio Code 用户界面和 Visual Studio Code 服务器。服务器部分负责加载源代码，启动应用程序，运行调试器，启动终端进程等其他活动。用户界面部分通过与服务器通信提供 Windows 用户界面功能。

远程扩展有各种不同的版本：

+   Remote-WSL，在 WSL 中运行服务器

+   Remote-SSH，允许您通过 SSH 连接到远程机器来运行服务器

+   Remote-Containers，允许您使用容器来运行服务器

我们将在本章的其余部分介绍 Remote-WSL，下一章将介绍 Remote-Containers。有关 Remote-Development 扩展的更多信息（包括 Remote-SSH），请参阅 https://code.visualstudio.com/docs/remote/remote-overview。让我们开始使用 Remote-WSL。

# 开始使用 Remote-WSL

Remote-WSL 扩展包含在 Remote-Development 扩展包中（[`marketplace.visualstudio.com/items?itemName=ms-vscode-remote.vscode-remote-extensionpack`](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.vscode-remote-extensionpack)），它提供了一种简单的方式来一键安装 Remote-WSL、Remote-SSH 和 Remote-Containers。如果你只想安装 Remote-WSL，请在这里进行安装：[`marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-wsl`](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-wsl)。

要跟随本书进行操作，请确保在 Linux 发行版中克隆了本书的代码。你可以在[`github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques`](https://github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques)找到代码。

示例代码使用 Python 3，如果你使用的是最新版本的 Ubuntu，它应该已经安装好了。你可以通过在 Linux 发行版中运行`python3 -c 'print("hello")'`来测试是否安装了 Python 3。如果命令成功完成，则说明一切准备就绪。如果没有，请参考 Python 文档中的安装说明：[`wiki.python.org/moin/BeginnersGuide/Download`](https://wiki.python.org/moin/BeginnersGuide/Download)。

现在让我们在 Visual Studio Code 中打开示例代码。

## 使用 Remote-WSL 打开文件夹

安装完 Remote-WSL 后，打开 Visual Studio Code 并从命令面板（*Ctrl* + *Shift* + *P*）选择**Remote-WSL: New Window**：

![图 9.3 - 显示命令面板中的 Remote-WSL 命令的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.3_B16412.jpg)

图 9.3 - 显示命令面板中的 Remote-WSL 命令的屏幕截图

此屏幕截图显示 Remote-WSL 扩展添加的新命令，选择**Remote-WSL: New Window**。这将打开一个新的 Visual Studio Code 窗口，在默认的 WSL 发行版中启动 Visual Studio Code 服务器并连接到它。如果你想选择连接的发行版，请选择**Remote-WSL: New Window using Distro…**选项。

新的 Visual Studio Code 窗口打开后，窗口的左下角将显示**WSL: Ubuntu-18.04**（或者你打开的其他发行版），表示此实例的 Visual Studio Code 通过 Remote-WSL 连接。

现在，我们可以从命令面板中选择**File: Open Folder…**来打开示例代码。在没有通过 Remote-WSL 连接时，在 Visual Studio Code 中执行此操作将打开标准的 Windows 文件对话框。然而，由于我们通过 Remote-WSL 连接，这个命令现在会提示我们选择连接的发行版中的一个文件夹：

![图 9.4 - 显示 Remote-WSL 文件夹选择器的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.4_B16412.jpg)

图 9.4 - 显示 Remote-WSL 文件夹选择器的屏幕截图

此屏幕截图显示从 WSL 分发文件系统中选择要打开的文件夹。请注意，我将本书的代码克隆到了`home`文件夹中的`wsl-book`中。根据你保存代码的位置，你可能会有一个类似于`/home/<your-user>/WSL-2-Tips-Tricks-and-Techniques/chapter-09/web-app`的路径。打开文件夹后，Visual Studio 开始处理内容，并提示你安装推荐的扩展（如果你还没有安装 Python 扩展）：

![图 9.5 - 显示推荐扩展提示的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.5_B16412.jpg)

图 9.5 - 显示推荐扩展提示的屏幕截图

此屏幕截图中的提示出现是因为您刚刚打开的文件夹包含一个列出 Python 扩展的`.vscode/extensions.json`文件。当提示出现时，要么单击**Install All**安装扩展，要么单击**Show Recommendations**在安装之前检查扩展。请注意，即使您之前在使用 Remote-WSL 之前已在 Visual Studio Code 中安装了 Python 扩展，您也可能会收到提示：

![图 9.6 - 显示在 Windows 中安装了 Python 但未安装 WSL 的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.6_B16412.jpg)

图 9.6 - 显示在 Windows 中安装了 Python 但未安装 WSL 的屏幕截图

此屏幕截图显示了 Visual Studio Code 中的**EXTENSIONS**视图，指示 Python 扩展已在 Windows 中安装，并提示我们安装当前项目所加载的 WSL 发行版的 Remote-WSL。如果您看到此提示，请单击**Install**按钮以在 WSL 中安装。

此时，我们在 Windows 中运行 Visual Studio Code 用户界面，并连接到在我们的 WSL 发行版中运行的服务器组件。服务器已加载了 Web 应用程序的代码，并且我们已安装了 Python 扩展，该扩展现在在服务器中运行。

有了这个设置，让我们看看如何在调试器下运行代码。

## 运行应用程序

要运行应用程序，我们首先需要确保 Python 扩展正在使用正确的 Python 版本（我们想要 Python 3）。为此，请查看 Visual Studio Code 窗口底部的状态栏，直到看到类似于**Python 2.7.18 64 位**的内容。单击此部分会弹出 Python 版本选择器：

![图 9.7 - 显示 Python 版本选择器的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.7_B16412.jpg)

图 9.7 - 显示 Python 版本选择器的屏幕截图

如此屏幕截图所示，版本选择器显示它检测到的任何 Python 版本，并允许您选择您想要的版本（在这里，我们选择了 Python 3 版本）。请注意，此列表中显示的路径都是 Linux 路径，确认 Python 扩展正在 WSL 中的 Visual Studio Code 服务器中运行。如果您喜欢使用 Python 虚拟环境（[`docs.python.org/3/library/venv.html`](https://docs.python.org/3/library/venv.html)）并为项目创建了一个虚拟环境，这些虚拟环境也会显示在此列表中供您选择。

在运行应用程序之前，我们需要安装依赖项。从命令面板中选择`pip3 install -r requirements.txt`以安装我们的依赖项。

提示

如果您尚未安装 pip3，请运行`sudo apt-update && sudo apt install python3-pip`进行安装。

或者，按照此处的说明进行操作：[`packaging.python.org/guides/installing-using-linux-tools/`](https://packaging.python.org/guides/installing-using-linux-tools/)。

接下来，从`app.py`打开`app.py`，我们可以通过按下*F5*来启动调试器，这将提示您选择要使用的配置：

![图 9.8 - 显示 Python 配置选择器的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.8_B16412.jpg)

图 9.8 - 显示 Python 配置选择器的屏幕截图

此屏幕截图显示了 Python 扩展允许您选择的一组常见调试选项。我们将在稍后看到如何配置它以实现完全灵活性，但现在选择**Flask**。这将使用 Flask 框架启动应用程序并附加调试器：

![图 9.9 - 显示在调试器下运行应用程序的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.9_B16412.jpg)

图 9.9 - 显示在调试器下运行应用程序的屏幕截图

在上一个屏幕截图中，您可以看到已打开集成终端窗口，并且 Visual Studio Code 已启动了我们的 Flask 应用程序。当应用程序启动时，它会输出它正在侦听的 URL（在此示例中为`http://127.0.0.1:5000`）。将光标悬停在此链接上会提示您使用*Ctrl* + *单击*打开链接。这样做将在默认浏览器中打开 URL：

![图 9.10-浏览器中显示 Web 应用程序的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.10_B16412.jpg)

图 9.10-浏览器中显示 Web 应用程序的屏幕截图

此屏幕截图显示了浏览器中 Web 应用程序的输出，其中包括 Web 应用程序服务器正在运行的操作系统名称和内核版本。同样，这证明了虽然 Visual Studio Code 用户界面在 Windows 中运行，但所有代码都在我们的 WSL 分发中处理和运行。Visual Studio Code 的 Remote-WSL 和 WSL 用于本地主机地址的流量转发的组合为我们提供了跨 Windows 和 Linux 的丰富和自然的体验。

到目前为止，我们只是将调试器用作启动应用程序的便捷方式。接下来，让我们看看如何使用调试器逐步执行代码。

## 调试我们的应用程序

在本节中，我们将介绍如何在调试器中逐步查看项目中的代码。同样，这使我们可以使用 Windows 中的 Visual Studio Code 用户界面连接到和调试在 WSL 分发中运行的应用程序。

在上一节中，我们看到了如何使用*F5*运行 Python 应用程序，并提示我们选择要使用的配置（我们选择了*Flask*）。由于我们还没有为项目配置调试器，因此每次都会提示我们选择环境。在深入研究调试器之前，让我们设置配置，以便*F5*自动正确启动我们的应用程序。为此，请打开**RUN**视图，可以通过按下*Ctrl* + *Shift* + *D*或从命令面板中选择**Run: Focus on Run View**命令来打开：

![图 9.11-Visual Studio Code 中显示运行视图的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.11_B16412.jpg)

图 9.11-Visual Studio Code 中显示运行视图的屏幕截图

此屏幕截图显示了`launch.json`文件。您将收到与*图 9.7*中相同的一组选项，并且应再次选择我们打开的文件夹中的`.vscode/launch.json`文件：

```
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Flask",
            "type": "python",
            "request": "launch",
            "module": "flask",
            "env": {
                "FLASK_APP": "app.py",
                "FLASK_ENV": "development",
                "FLASK_DEBUG": "0"
            },
            "args": [
                "run",
                "--no-debugger",
                "--no-reload"
            ],
            "jinja": true
        }
    ]
}
```

如此内容所示，`launch.json`包含一个`env`属性。

配置了调试选项后，让我们切换回`app.py`文件并设置一个断点。在`app.py`中，我们有一个`home`方法，它返回一些 HTML 并包含`get_os_info`函数的输出。在该函数的`return`语句处导航并按下*F9*添加一个断点（还有其他方法可以做到这一点-请参阅 https://code.visualstudio.com/docs/editor/debugging）。现在，我们可以按下*F5*运行我们的应用程序，当它处理请求时，它将在调试器中暂停。要触发断点，请像之前一样打开浏览器并切换回 Visual Studio Code：

![图 9.12-Visual Studio Code 在 WSL 中调试 Python 应用程序的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.12_B16412.jpg)

图 9.12-Visual Studio Code 在 WSL 中调试 Python 应用程序的屏幕截图

此屏幕截图显示了 Visual Studio Code 调试我们的应用程序。在左侧，我们可以看到局部变量（例如，`sysname`变量的内容）和调用堆栈。我们可以使用窗口顶部的控件（或它们的键盘快捷键）来恢复执行或逐步执行代码。窗口底部显示了用于运行应用程序的终端，我们可以将其切换到`sysname="Hello"`，然后按下*F5*恢复应用程序。切换回浏览器，您将在浏览器的输出中看到`Hello`，显示我们在调试器中更新了变量的值。

在这里，我们看到了 Visual Studio Code 对多种语言的丰富支持（通过安装语言支持扩展）。通过安装和使用*Remote-WSL*扩展，我们可以在 Windows 中获得 Visual Studio Code 的丰富功能，并在 WSL 中执行所有代码服务。在这个例子中，我们演示了在 WSL 中运行的所有代码服务：Python 解释器、语言服务以实现重构、调试器和正在调试的应用程序。所有这些执行都发生在 WSL 中，因此我们可以在 Linux 中设置环境，然后在开发应用程序时在其上方拥有丰富的用户界面。

现在我们已经了解了核心体验，我们将深入了解一些使用 Remote-WSL 的技巧。

# 使用 Remote-WSL 的技巧

本节将介绍一些技巧，可以帮助您在使用 Visual Studio Code 和 Remote-WSL 时进一步优化您的体验。

## 从终端加载 Visual Studio Code

在 Windows 中，您可以使用`code <路径>`命令从终端启动 Visual Studio Code，以打开指定的路径。例如，您可以使用`code .`来打开当前文件夹（`.`）在 Visual Studio Code 中。实际上，这使用了一个`code.cmd`脚本文件，但 Windows 允许您省略扩展名。

在使用 WSL 时，通常会打开一个终端，并且使用 Remote-WSL，您还可以获得一个`code`命令。因此，您可以在 WSL 的终端中导航到项目文件夹并运行`code .`，它将启动 Visual Studio Code 并使用 Remote-WSL 扩展打开指定的文件夹（在这种情况下是当前文件夹）。这种集成是一个很好的选择，可以在 Windows 和 WSL 环境之间保持一致和集成。

在这里，我们看到了如何从终端进入 Visual Studio Code。接下来，我们将看相反的情况。

## 在 Windows 终端中打开外部终端

有时候你在 Visual Studio Code 中工作，想要一个新的终端来运行一些命令。Visual Studio Code 在 Visual Studio Code 扩展视图中有`Windows 终端集成`，或者打开 https://marketplace.visualstudio.com/items?itemName=Tyriar.windows-terminal。安装完成后，会有一些新的命令可用：

![图 9.13 - 展示新的 Windows 终端命令的截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.13_B16412.jpg)

图 9.13 - 展示新的 Windows 终端命令的截图

这个截图展示了命令面板中的新命令。**打开**命令使用 Windows 终端中的默认配置打开 Visual Studio Code 工作区文件夹。**打开活动文件夹**命令在默认配置中打开包含当前打开文件的文件夹。另外两个命令**使用配置文件打开**对应于前面的命令，但允许您选择使用哪个 Windows 终端配置文件打开路径。

除了从命令面板中访问的命令外，该扩展还为资源管理器视图中的文件和文件夹添加了右键菜单的新项目：

![图 9.14 - 展示右键菜单命令的截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.14_B16412.jpg)

图 9.14 - 展示右键菜单命令的截图

在这个截图中，我在资源管理器视图中点击了一个文件夹，扩展添加了两个菜单项，用于在 Windows 终端中打开路径。其中第一个菜单项在默认配置中打开路径，第二个菜单项会提示打开路径。

这个扩展可以快速方便地在 Visual Studio Code 项目的上下文中打开一个 Windows 终端实例，让您保持流畅和高效。

接下来，我们将介绍一些使用 Git 的技巧。

## 使用 Visual Studio Code 作为您的 Git 编辑器

Visual Studio Code 提供了与 Git 存储库一起工作的集成可视化工具。根据个人喜好，您可以使用`git`命令行工具来进行一些或全部的 Git 交互。对于某些操作，Git 会打开一个临时文件以获取进一步的输入，例如在合并提交上获取提交消息或确定在交互式 rebase 上采取哪些操作。

除非您配置了其他编辑器，否则 Git 将使用`vi`作为其默认编辑器。如果您熟悉`vi`，那很好，但如果您更喜欢使用 Visual Studio Code，我们可以利用本章前面看到的`code`命令。

要配置 Git 使用 Visual Studio Code，我们可以运行`git config --global core.editor "code --wait"`。`--global`开关设置所有存储库的配置值（除非它们覆盖它），我们正在设置`core.editor`值，该值控制`git`使用的编辑器。我们为此设置分配的值是`code --wait`，它使用我们在上一节中看到的`code`命令。运行`code`命令而不使用`--wait`开关会启动 Visual Studio Code 然后退出（保持 Visual Studio Code 运行），这通常是在使用它打开文件或文件夹时所希望的行为。但是，当`git`启动编辑器时，它期望进程阻塞直到文件关闭，而`--wait`开关提供了这种行为：

![图 9.15 - 显示 Visual Studio Code 作为 WSL 的 Git 编辑器的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.15_B16412.jpg)

图 9.15 - 显示 Visual Studio Code 作为 WSL 的 Git 编辑器的屏幕截图

在这个屏幕截图中，您可以在底部的终端中看到一个交互式的`git rebase`命令，以及在配置了 Git 编辑器后加载到 Visual Studio Code 中的`git-rebase-todo`文件，用于捕获操作。

接下来，我们将继续查看 Git，探索查看 Git 历史记录的方法。

## 查看 Git 历史记录

在使用 Git 进行版本控制的项目中工作时，您可能会想要在某个时候查看提交历史记录。有各种方法可以实现这一点，您可能也有自己首选的工具。尽管界面风格简单，但我经常使用`gitk`，因为它是普遍存在的，作为 Git 安装的一部分包含在其中。在 Windows 上工作时，您可以直接从 Git 存储库的文件夹中运行`gitk`。在 WSL 中，我们需要运行`gitk.exe`以便启动 Windows 应用程序（请注意，这需要在 Windows 上安装 Git）：

![图 9.16 - 显示从 WSL 运行的 gitk.exe 的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.16_B16412.jpg)

图 9.16 - 显示从 WSL 运行的 gitk.exe 的屏幕截图

在这个屏幕截图中，您可以看到从 WSL Git 存储库运行的`gitk` Windows 应用程序，并通过文件系统映射访问内容。如果您有其他首选的用于查看 Git 历史记录的 Windows 应用程序，那么这种方法也可以工作，只要该应用程序在您的路径中。如果在运行这些命令时忘记添加`.exe`，您可能希望查看*第五章*，*Linux 到 Windows 的互操作性*，*为 Windows 应用程序创建别名*部分。

由于 Windows 应用程序通过`\\wsl$`共享使用 Windows 到 Linux 文件映射，您可能会注意到对于大型 Git 存储库，应用程序加载速度较慢，因为这种映射的开销较大。另一种方法是在 Visual Studio Code 中使用扩展，例如**Git Graph**（https://marketplace.visualstudio.com/items?itemName=mhutchie.git-graph）：

![图 9.17 - 显示在 Visual Studio Code 中的 Git Graph 扩展](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_9.17_B16412.jpg)

图 9.17 - 显示 Visual Studio Code 中的 Git Graph 扩展

这个截图显示了使用**Git Graph**扩展查看的 Git 历史记录。通过使用 Visual Studio Code 扩展来渲染 Git 历史记录，扩展可以由在 WSL 中运行的服务器组件来运行。这样可以直接访问文件来查询 Git 历史记录，并避免了 Windows 应用程序的性能开销。

# 概述

在本章中，您已经对 Visual Studio Code 有了一个概述，并且看到它是一个灵活的编辑器，具有丰富的扩展生态系统，为各种语言提供支持，并为编辑器添加额外的功能。

其中一个扩展是 Remote-WSL，它允许将编辑器分为两部分，用户界面部分在 Windows 中运行，其他功能在 WSL 中运行（包括文件访问、语言服务和调试器）。

这个功能使您能够无缝地使用 Visual Studio Code 的丰富功能（包括扩展），但是您的源代码和应用程序都在 WSL 中运行。通过这种方式，您可以充分利用适用于您的 WSL 发行版的工具和库。

在下一章中，我们将探索另一个 Visual Studio Code Remote 扩展，这次将研究在容器中运行服务以自动化开发环境并提供依赖项的隔离。


# 第十章：Visual Studio Code 和容器

在*第九章*，*Visual Studio Code 和 WSL*中，我们看到 Visual Studio Code 编辑器允许将用户界面与与我们的代码交互和运行代码的其他功能分离。通过 WSL，这使我们可以在运行我们项目的所有关键部分的 Linux 中保持熟悉的基于 Windows 的用户界面。除了允许代码交互在 WSL 中的服务器组件中运行外，Visual Studio Code 还允许我们通过 SSH 连接到代码服务器或在容器中运行它。能够在容器中运行是由**Remote-Containers**扩展提供的，本章将重点介绍如何使用此功能。我们将看到如何使用这些开发容器（或**dev container**）来封装我们的项目依赖项。通过这样做，我们可以更容易地将人们引入我们的项目，并获得一种优雅的方式来隔离可能发生冲突的工具集。

在本章中，我们将介绍以下主要内容：

+   介绍 Visual Studio Code Remote-Containers

+   安装 Remote-Containers

+   创建一个 dev 容器

+   在开发容器中使用容器化应用程序

+   在开发容器中使用 Kubernetes

+   使用开发容器的技巧

在本章中，您需要安装 Visual Studio Code - 请参阅*第九章*，*Visual Studio Code 和 WSL*，*介绍 Visual Studio Code*部分了解更多详细信息。我们将通过介绍 Visual Studio Code 的 Remote-Containers 扩展并将其安装来开始本章。

# 介绍 Visual Studio Code Remote-Containers

Visual Studio Code 的 Remote-Containers 扩展作为 Remote-Development 扩展包的一部分，与**Remote-WSL**和**Remote-SSH**一起。所有这些扩展都允许您将用户界面方面与代码交互分离，例如加载、运行和调试代码。通过 Remote-Containers，我们指示 Visual Studio Code 在我们在**Dockerfile**中定义的容器内运行这些代码交互（请参阅*第七章*，*在 WSL 中使用容器*，*介绍 Dockerfiles*部分）。

当 Visual Studio Code 在开发容器中加载我们的项目时，它经过以下步骤：

1.  从 Dockerfile 构建容器镜像

1.  使用生成的镜像运行容器，将源代码挂载到容器中。

1.  在容器中为用户界面安装 VS 代码服务器

通过这些步骤，我们得到一个包含我们的 Dockerfile 描述的依赖项的容器镜像。通过将代码挂载到容器内部，代码可以在容器内部使用，但只有一份代码的副本。

在开发项目中，通常会有一份工具或先决条件列表，需要安装这些工具以准备好与项目一起工作。如果你很幸运，这个列表甚至会是最新的！通过使用*dev containers*，我们可以用 Dockerfile 中的一系列步骤替换文档中的工具列表来执行这些步骤。由于这些镜像可以重新构建，安装工具的标准方式现在变成了 Dockerfile。由于这是源代码控制的一部分，所以这些所需工具的更改将与其他开发人员共享，他们只需从 Dockerfile 重新构建他们的 dev 容器镜像即可更新他们的工具集。

开发容器的另一个好处是依赖项安装在容器中，因此是隔离的。这使我们能够为不同项目创建具有相同工具的不同版本的容器（例如 Python 或 Java），而不会发生冲突。这种隔离还允许我们在项目之间独立更新工具的版本。

让我们来看看如何安装 Remote-Containers 扩展。

# 安装 Remote-Containers

要使用 Remote-Containers 扩展，您需要安装它，并且还需要在 WSL 中安装和访问 Docker。请参阅*第七章*，*在 WSL 中使用容器*，*使用 WSL 安装和使用 Docker*部分以了解如何配置。如果您已经安装了 Docker Desktop，请确保将其配置为使用**基于 WSL 2 的引擎**。WSL 2 引擎使用在 WSL 2 中运行的 Docker 守护程序，因此您的代码文件（来自 WSL 2）可以直接挂载到容器中，而无需经过 Linux 到 Windows 文件共享。这种直接挂载可以提供更好的性能，确保文件事件被正确处理，并使用相同的文件缓存（有关更多详细信息，请参阅此博文：[`www.docker.com/blog/docker-desktop-wsl-2-best-practices/)`](https://www.docker.com/blog/docker-desktop-wsl-2-best-practices/)）。

一旦您配置好了 Docker，下一步是安装 Remote-Containers 扩展。您可以在 Visual Studio Code 的**EXTENSIONS**视图中搜索`Remote-Containers`来完成此操作，或者访问[`marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers`](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)。

安装了扩展后，让我们看看如何创建开发容器。

# 创建开发容器

要将开发容器添加到项目中，我们需要创建一个包含两个文件的`.devcontainer`文件夹：

+   `Dockerfile`用于描述要构建和运行的容器映像

+   `devcontainer.json`以添加其他配置

这些文件的组合将为我们提供一个单容器配置。Remote-Containers 还支持使用**Docker Compose**的多容器配置（参见[`code.visualstudio.com/docs/remote/create-dev-container#_using-docker-compose`](https://code.visualstudio.com/docs/remote/create-dev-container#_using-docker-compose)），但在本章中，我们将重点关注单容器场景。

本书附带的代码包含一个示例项目，我们将使用它来探索开发容器。请确保从[`github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques`](https://github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques)在 Linux 发行版中克隆代码。克隆代码后，在 Visual Studio Code 中打开`chapter-10/01-web-app`文件夹（还有一个`chapter-10/02-web-app-completed`文件夹，其中包含了本节中的所有步骤作为参考）。这个示例代码还没有开发容器定义，所以让我们看看如何添加它。

## 添加和打开开发容器定义

开发容器的第一步是创建**开发容器定义**，Remote-Containers 扩展在这方面为我们提供了一些帮助。在 Visual Studio Code 中打开示例项目后，从命令面板中选择**Remote-Containers: Add Development Container Configuration Files…**，然后您将被提示选择一个配置：

![图 10.1-显示开发容器配置列表的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_10.1_B16412.jpg)

图 10.1-显示开发容器配置列表的屏幕截图

如此屏幕截图所示，我们可以从一系列预定义的开发容器配置中选择。对于示例项目，请选择`.devcontainer`文件夹，并配置`devcontainer.json`和`Dockerfile`以使用 Python 3。添加这些文件后，您应该会看到以下提示：

![图 10.2-显示重新在容器中打开提示的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_10.2_B16412.jpg)

图 10.2-显示重新在容器中打开提示的屏幕截图

当 Visual Studio Code 检测到您打开了一个带有开发容器定义的文件夹时，会出现此提示。点击**在容器中重新打开**以在开发容器中打开文件夹。如果您错过了提示，可以使用命令面板中的**Remote-Containers: Reopen in Container**命令来实现相同的功能。

选择重新在容器中打开文件夹后，Visual Studio Code 将重新启动并开始构建容器镜像以运行代码服务器。您将看到一个通知：

![Figure 10.3 – A screenshot showing the Starting with Dev Container notification](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_10.3_B16412.jpg)

Figure 10.3 – A screenshot showing the Starting with Dev Container notification

此截图显示了开发容器正在启动的通知。如果您点击通知，将会进入**TERMINAL**视图中的**Dev Containers**窗格，显示构建和运行容器的命令和输出。当您开始自定义开发容器定义时，此窗口对于调试场景非常有用，例如当您的容器镜像无法构建时。现在我们已经在开发容器中打开了项目，让我们开始探索它吧。

## 在开发容器中工作

一旦开发容器构建和启动完成，您将在`devcontainer.json`文件的`name`属性中看到示例代码的内容：

```
{
    "name": "chapter-10-01-web-app",
...
```

在`devcontainer.json`的这个片段中，开发容器的名称已更改为`chapter-10-01-web-app`。此更改将在下次构建和加载开发容器时生效。如果您有时同时加载多个开发容器，将名称设置得有意义尤为有帮助，因为它会显示在窗口标题中。

接下来，让我们打开包含示例应用程序代码的`app.py`文件：

![Figure 10.4 – A screenshot showing an import error in app.py](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_10.4_B16412.jpg)

Figure 10.4 – A screenshot showing an import error in app.py

在此截图中，您可以看到导入 Flask 包的行下面的红色下划线，这在 Python 扩展加载和处理文件后显示。此错误表示 Python 无法找到 Flask 包。希望这是有意义的-所有的工具都在一个只安装了 Python 的容器中运行，没有其他东西。让我们快速修复这个问题。使用*Ctrl* + *`*（反引号）打开集成终端，或者使用`pip3 install -r requirements.txt`安装`requirements.txt`中列出的要求（包括 Flask）。安装了要求后，Python 语言服务器最终会更新以删除红色下划线警告。

在本章后面，我们将介绍如何在构建容器时自动安装所需的内容，以提供更流畅的体验；但是现在我们已经准备好了，让我们运行代码吧。

## 运行代码

示例代码包括一个描述如何启动我们的代码的`.vscode/launch.json`文件。该文件允许我们配置传递给进程的命令行参数和应设置的环境变量等内容。有关`launch.json`的介绍和从头开始创建它的内容，请参见*第九章*，*Visual Studio Code 和 WSL*，*调试我们的应用程序*部分。

通过`launch.json`，我们只需按下*F5*即可在调试器下启动我们的应用程序。如果您想看到交互式调试器的效果，请使用*F9*设置断点（`get_os_info`函数中的`return`语句是一个好的位置）。

启动后，您将在**TERMINAL**视图中看到调试器命令的执行和相应的输出：

```
* Serving Flask app "app.py"
 * Environment: development
 * Debug mode: off
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
```

在这个输出中，你可以看到应用程序启动并显示了它正在监听的地址和端口（`http://127.0.0.1:5000`）。当你用鼠标悬停在这个地址上时，你会看到一个弹出窗口，显示你可以使用*Ctrl* + 单击来打开链接。这样做将会在你的默认 Windows 浏览器中打开该地址，并且如果你设置了断点，你会发现代码已经在那个点暂停，以便你检查变量等。一旦你完成了对调试器的探索，按下*F5*继续执行，你将在浏览器中看到渲染后的响应：

![Figure 10.5 – 一个截图显示了 Python 应用在 Windows 浏览器中的网页](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_10.5_B16412.jpg)

Figure 10.5 – 一个截图显示了 Python 应用在 Windows 浏览器中的网页

这个截图显示了浏览器加载了我们的 Python 应用的网页。请注意主机名（在截图中为`831c04e3574c`，但是你会看到一个不同的 ID，因为每个容器都会改变），这是短容器 ID，它被设置为容器实例中运行应用程序的主机名。我们能够从 Windows 加载网页，是因为 Remote-Containers 扩展自动为我们设置了端口转发。这个端口转发在 Windows 上监听端口`5000`，并将流量转发到我们的 Python 应用程序所在的容器中的端口`5000`，以进行监听和响应。

此时，我们在 WSL 中的 Docker 中运行了一个容器，其中包含了我们的所有开发工具（包括 Python 和 Visual Studio Code 服务器），我们能够以我们期望的丰富、交互式的方式与代码一起工作。我们可以轻松地在调试器中启动代码，逐步执行代码并检查变量，然后从 Windows 与我们的 Web 应用程序进行交互。所有这些都像在主机上运行代码一样顺利，但我们拥有开发容器带来的隔离和自动化开发环境的所有优势。

接下来，我们将探索如何自定义开发容器定义，同时将我们的应用程序作为容器在开发容器中打包和运行。

# 在开发容器中使用容器化应用程序

到目前为止，我们已经看到了如何使用开发容器来开发应用程序，但是如果我们想要开发一个将自身打包并在容器中运行的应用程序，可能是在 Kubernetes 中呢？在本节中，我们将专注于这种情况，看看如何从开发容器内部构建和运行我们应用程序的容器镜像。

我们将再次使用本书的附带代码作为本节的起点。确保你在 Linux 发行版中从[`github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques`](https://github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques)克隆代码。代码克隆完成后，用 Visual Studio Code 打开`chapter-10/03-web-app-kind`文件夹（还有一个`chapter-10/04-web-app-kind-completed`文件夹，其中包含了本节中所有步骤的参考）。`03-web-app-kind`文件夹包含一个与我们刚刚使用的 Web 应用程序非常相似的 Web 应用程序，但是添加了一些额外的文件，以帮助我们在本章后面将应用程序集成到 Kubernetes 中。

为了能够在 Docker 中使用该应用程序，我们需要经历一些类似于我们在*第七章*中所经历的步骤，即在 WSL 中使用容器的*构建和运行 Web 应用程序*部分，只是这一次，我们将在我们的开发容器中进行操作：

1.  在开发容器中设置 Docker。

1.  构建应用程序 Docker 镜像。

1.  运行应用程序容器。

让我们首先看看如何设置开发容器，以允许我们构建应用程序容器镜像。

## 在开发容器中设置 Docker

启用构建 Docker 镜像的第一步是在 Visual Studio Code 中安装`docker` `.devcontainer/Dockerfile`并添加以下内容：

```
RUN apt-get update \
     && export 
DEBIAN_FRONTEND=noninteractive \"
    # Install docker
    && apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common lsb-release \
    && curl -fsSL https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]')/gpg | apt-key add - 2>/dev/null \
    && add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]') $(lsb_release -cs) stable" \
    && apt-get update \
    && apt-get install -y docker-ce-cli \
    # Install docker (END)
    # Install icu-devtools
    && apt-get install -y icu-devtools \ 
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*
```

在此代码片段中，请注意`# Install docker`和`# Install docker (END)`之间的行。这些行已添加以遵循 Docker 文档中的步骤，以添加`apt`存储库，然后使用该存储库来`apt-get install` `docker-ce-cli`软件包。此时，重新构建和打开开发容器将为您提供一个带有`docker` CLI 的环境，但没有守护程序与其通信。

我们已经在主机上设置了 Docker，并且 Visual Studio Code 使用此提供的 Docker 守护程序来构建和运行我们用于开发的开发容器。要在容器内构建和运行 Docker 镜像，您可以考虑在开发容器内安装 Docker。这是可能的，但可能会变得非常复杂并且会增加性能问题。相反，我们将在开发容器内重用主机上的 Docker 守护程序。在 Linux 上，默认与 Docker 的通信是通过`/var/run/docker.sock`套接字进行的。使用`docker` CLI 运行容器时，可以使用`--mounts`开关挂载套接字（[`docs.docker.com/storage/bind-mounts/`](https://docs.docker.com/storage/bind-mounts/)）。对于开发容器，我们可以在`.devcontainer/devcontainer.json`中使用`mounts`属性指定此内容：

```
"mounts": [
    // mount the host docker socket (for Kind and docker builds)
    "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"
],
```

此代码段显示了`devcontainer.json`中的`mounts`属性，该属性指定 Visual Studio Code 在运行我们的开发容器时要使用的挂载点。此属性是一个挂载字符串的数组，在这里我们指定了我们想要一个`bind`挂载（即从主机挂载），将主机上的`/var/run/docker.sock`挂载到开发容器内的相同值。这样做的效果是使主机上的 Docker 守护程序的套接字在开发容器内可用。

此时，在终端中已经安装了`docker` CLI 供您使用。您运行的任何`docker`命令都将针对 Docker Desktop 守护程序执行；因此，例如运行`docker ps`以列出容器将包括开发容器在其输出中：

```
# docker ps
CONTAINER ID        IMAGE                                                            COMMAND                  CREATED             STATUS              PORTS               NAMES
6471387cf184        vsc-03-web-app-kind-44349e1930d9193efc2813 97a394662f             "/bin/sh -c 'echo Co…"   54 seconds ago       Up 53 seconds  
```

在开发容器中终端中执行的`docker ps`命令的输出包括开发容器本身，确认 Docker 命令正在连接到主机 Docker 守护程序。

提示

如果您在更新 Dockerfile 和`devcontainer.json`之前已经打开了开发容器（或者在修改这些文件的任何时间），您可以运行**Remote-Containers: Rebuild and reopen in Container**命令。此命令将重新运行开发容器的构建过程，然后重新打开它，将您对开发容器的更改应用到其中。

现在我们已经安装和配置了 Docker，让我们来构建我们应用程序的容器镜像。

## 构建应用程序的 Docker 镜像

要构建我们应用程序的 Docker 镜像，我们可以运行`docker build`命令。由于 Docker CLI 配置为与主机 Docker 守护程序通信，我们从开发容器内构建的任何镜像实际上都是在主机上构建的。这消除了您可能期望从开发容器中获得的一些隔离性，但我们可以通过确保我们使用的镜像名称是唯一的来解决这个问题，以避免与其他项目发生名称冲突。

示例代码的根文件夹中已经有一个 Dockerfile，我们将使用它来构建应用程序的 Docker 镜像（不要与`.devcontainer/Dockerfile`混淆，该文件用于构建开发容器）。Dockerfile 在`python`基础镜像上构建，然后复制我们的源代码并配置启动命令。有关 Dockerfile 的更多详细信息，请参考*第七章*，*在 WSL 中使用容器*，*介绍 Dockerfiles*部分。

要构建应用程序镜像，请像在本章前面所做的那样打开集成终端，并运行以下命令来构建容器镜像：

```
docker build -t simple-python-app-2:v1 -f Dockerfile .
```

此命令将拉取 Python 镜像（如果不存在），并在输出`Successfully tagged simple-python-app-2:v1`之前运行 Dockerfile 中的每个步骤。

现在我们已经构建了应用程序镜像，让我们运行它。

## 运行应用程序容器

要运行我们的镜像，我们将使用`docker run`命令。从 Visual Studio Code 的集成终端中运行以下命令：

```
# docker run -d --network=container:$HOSTNAME --name chapter-10-example simple-python-app-2:v1 
ffb7a38fc8e9f86a8dd50ed197ac1a202ea7347773921de6a34b93cec 54a1d95
```

在此输出中，您可以看到我们正在运行一个名为`chapter-10-example`的容器，使用我们之前构建的`simple-python-app-2:v1`镜像。我们指定了`--network=container:$HOSTNAME`，这将新创建的容器放在与开发容器相同的 Docker 网络中。请注意，我们使用`$HOSTNAME`来指定开发容器的 ID，因为容器 ID 用作运行容器中的机器名称（正如我们在*第七章**中看到的，在 WSL 中使用容器的构建和运行* *Docker*部分）。有关`--network`开关的更多信息，请参阅[`docs.docker.com/engine/reference/run/#network-settings`](https://docs.docker.com/engine/reference/run/#network-settings)。我们可以通过从集成终端运行`curl`来确认我们能够访问运行容器中的 Web 应用程序：

```
# curl localhost:5000
<html><body><h1>Hello from Linux (4.19.104-microsoft-standard) on ffb7a38fc8e9</h1></body></html>
```

在此输出中，您可以看到 Web 应用程序对`curl`命令的 HTML 响应。这证实了我们可以从开发容器内部访问该应用程序。

如果您尝试从 Windows 浏览器访问 Web 应用程序，它将无法连接。这是因为 Web 应用程序的容器端口已映射到开发容器的 Docker 网络中。幸运的是，Remote-Containers 提供了一个`5000`，我们可以使 Windows 中的 Web 浏览器也能访问运行在容器中的 Web 应用程序。

对于您希望以这种方式在主机上定期访问的开发容器端口，更新`devcontainer.json`非常方便：

```
"forwardPorts": [
    5000
]
```

在这个片段中，您可以看到`forwardPorts`属性。这是一个端口数组，您可以配置它们在运行开发容器时自动转发，以节省每次手动转发的步骤。

**注意**

作为使用`--network`开关运行 Web 应用程序容器的替代方法，我们可以配置开发容器使用主机网络（使用`--network=host`，如下一节所示）。使用这种方法，开发容器重用与主机相同的网络堆栈，因此我们可以使用以下命令运行 Web 应用程序容器：

`docker run -d -p 5000:5000 --name chapter-10-example simple-python-app-2:v1`

在此命令中，我们使用了`-p 5000:5000`来将 Web 应用程序端口 5000 暴露给主机，正如我们在*第七章**中看到的，在 WSL 中使用容器的构建和运行* *Docker*部分。

到目前为止，我们已经设置好了开发容器，使其连接到我们主机上的 Docker，并重用它来使用我们在开发容器中安装的 Docker CLI 进行构建和运行镜像。现在我们已经测试了为我们的 Web 应用程序构建容器镜像，并检查了它是否正确运行，让我们看看在从开发容器中工作时如何在 Kubernetes 中运行它。

# 在开发容器中使用 Kubernetes

现在我们有了一个可以从开发容器内部构建的 Web 应用程序的容器镜像，我们将看一下运行应用程序所需的步骤，以便能够在 Kubernetes 中运行我们的应用程序。这一部分相当高级（特别是如果您对 Kubernetes 不熟悉），所以可以跳到*与开发容器一起工作的提示*部分，稍后再回来阅读。

让我们首先看看如何设置用于与 Kubernetes 一起工作的开发容器。

## Kubernetes 与开发容器的选项

在 WSL 中使用 Kubernetes 的选项有很多。常见的选项在*第七章*中的*在 WSL 中设置 Kubernetes*部分中进行了概述。在该章节中，我们使用了 Docker 桌面中的 Kubernetes 集成，这是一种低摩擦的设置 Kubernetes 的方式。这种方法也可以用于开发容器，只需完成几个步骤（假设您已启用了 Docker 桌面集成）：

1.  挂载一个卷，将 WSL 中的`~/.kube`文件夹映射到开发容器中的`/root/.kube`，以共享连接到 Kubernetes API 的配置。

1.  在开发容器的 Dockerfile 中作为一步安装`kubectl` CLI 以便与 Kubernetes 一起使用。

第一步使用`devcontainer.json`中的挂载，就像我们在前一节中看到的一样（引用用户主文件夹的标准做法是使用环境变量 - 例如`${env:HOME}${env:USERPROFILE}/.kube`）。我们将在稍后介绍安装`kubectl`的第二步。在本章中，我们将探索一种不同的 Kubernetes 方法，但是在附带书籍的代码中有一个`chapter10/05-web-app-desktop-k8s`文件夹，其中包含已完成这两个步骤的开发容器。

虽然 Docker 桌面的 Kubernetes 集成很方便，但它增加了对主机配置的额外要求。默认情况下，开发容器只需要您安装了带有 Remote-Containers 的 Visual Studio Code 和正在运行的 Docker 守护程序，并且通过开发容器的内容满足了其余的项目要求。在 Docker 桌面中需要 Kubernetes 集成会稍微降低开发容器的可移植性。另一个考虑因素是使用 Docker 桌面集成意味着您正在使用在整个计算机上共享的 Kubernetes 集群。当您的项目涉及创建 Kubernetes 集成（如运算符或其他可能应用策略的组件）时，这种隔离的丧失可能特别重要。`kind`项目（[`kind.sigs.k8s.io/`](https://kind.sigs.k8s.io/)）提供了一种替代方法，允许我们使用 Docker 在开发容器内轻松创建和管理 Kubernetes 集群（实际上，kind 代表 Kubernetes in Docker）。如果您计划在开发容器中重用 kind，则这种方法也很有效。

## 在开发容器中设置 kind

在本节中，我们将逐步介绍在开发容器中安装`kind`（和`kubectl`）的步骤。这将允许我们使用`kind` CLI 在开发容器内创建 Kubernetes 集群，然后使用`kubectl`访问它们。为此，我们需要执行以下操作：

+   在 dev 容器的 Dockerfile 中添加安装 kind 和 kubectl 的步骤。

+   更新`devcontainer.json`以启用连接到 kind 集群。

要安装`kind`，打开`.devcontainer/Dockerfile`并添加以下`RUN`命令（在以`apt-get update`开头的`RUN`命令之后）。

```
# Install Kind
RUN curl -Lo ./kind https://github.com/kubernetes-sigs/kind/releases/download/v0.8.1/kind-linux-amd64 && \
    chmod +x ./kind && \
    mv ./kind /usr/local/bin/kind
```

此片段中的`RUN`命令遵循安装 kind 的文档（[`kind.sigs.k8s.io/docs/user/quick-start/#installation`](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)），并使用`curl`下载 kind 的发布二进制文件。

在上一个命令之后添加以下`RUN`命令以安装`kubectl`：

```
# Install kubectl
RUN curl -sSL -o /usr/local/bin/kubectl https://storage.googleapis.com/kubernetes-release/release/v1.19.0/bin/linux/amd64/kubectl \
    && chmod +x /usr/local/bin/kubectl
```

这个`RUN`步骤根据文档（[`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)）安装`kubectl`。这些命令中的第一个使用`curl`下载发布二进制文件（在本例中为版本`1.19.0`）。第二个命令使下载的二进制文件可执行。

现在我们已经配置好了`kind`和`kubectl`的安装，我们需要对`.devcontainer/devcontainer.json`进行一些更改。首先是在开发容器中添加一个`.kube`文件夹的卷：

```
"mounts": [
    // mount a volume for kube config
    "source=04-web-app-kind-completed-kube,target=/root/.kube,type=volume",
    // mount the host docker socket (for Kind and docker builds)
    "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"
],
```

这个片段显示了我们之前使用的`mounts`属性，用于将主机的 Docker 套接字与新配置的挂载绑定，以创建一个以`/root/.kube`文件夹为目标的卷。当我们运行`kind`创建一个 Kubernetes 集群时，它将把与集群通信的配置保存在这个文件夹中。通过添加一个卷，我们确保该文件夹的内容在开发容器的实例（和重建）之间持久存在，以便我们仍然可以连接到 Kubernetes 集群。

如前所述，`kind`将 Kubernetes API 端点列为`127.0.0.1`（本地 IP 地址）。这指的是主机，但是开发容器默认情况下位于一个隔离的 Docker 网络中。为了使开发容器能够使用`kind`生成的配置访问 Kubernetes API，我们可以通过更新`.devcontainer/devcontainer.json`将开发容器放入主机网络模式中：

```
"runArgs": [
    // use host networking (to allow connecting to Kind clusters)
    "--network=host"
],
```

在这个片段中，您可以看到`runArgs`属性。这允许我们配置附加参数，当 Remote-Containers 启动我们的开发容器时，它会将这些参数传递给`docker run`命令。在这里，我们设置了`--network=host`选项，它将在与主机相同的网络空间中运行容器（有关更多详细信息，请参见[`docs.docker.com/engine/reference/run/#network-settings`](https://docs.docker.com/engine/reference/run/#network-settings)）。

通过这些更改，我们可以重新构建和重新打开开发容器，然后准备创建一个 Kubernetes 集群并在其中运行我们的应用程序！

## 使用 kind 在 Kubernetes 集群中运行我们的应用程序

现在，我们已经准备好从开发容器内部创建一个 Kubernetes 集群了。要创建一个集群，我们将使用集成终端中的`kind` CLI：

![图 10.6 - 显示 kind 集群创建的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_10.6_B16412.jpg)

图 10.6 - 显示 kind 集群创建的屏幕截图

在这里，您可以看到运行`kind create cluster --name chapter-10-03`的输出。如果节点上没有容器镜像，`kind` CLI 会负责拉取容器镜像，然后在设置集群的步骤中更新输出。默认情况下，`kind`创建一个单节点集群，但是有一系列的配置选项，包括设置多节点集群（参见[`kind.sigs.k8s.io/docs/user/configuration/`](https://kind.sigs.k8s.io/docs/user/configuration/)）。

现在，我们可以使用这个集群来运行我们的应用程序（假设您已经在前一节中构建了容器镜像；如果没有，请运行`docker build -t simple-python-app-2:v1 -f Dockerfile.`）。

为了使我们的应用程序的容器镜像在`kind`集群中可用，我们需要运行`kind load`（参见[`kind.sigs.k8s.io/docs/user/quick-start/#loading-an-image-into-your-cluster`](https://kind.sigs.k8s.io/docs/user/quick-start/#loading-an-image-into-your-cluster)）：

```
# kind load docker-image --name chapter-10-03 simple-python-app-2:v1
Image: "simple-python-app-2:v1" with ID "sha256:7c085e8bde177aa0abd02c36da2cdc68238e672f49f0c9b888581b 9602e6e093" not yet present on node "chapter-10-03-control-plane", loading...
```

在这里，我们使用`kind load`命令将`simple-python-app-2:v1`镜像加载到我们创建的`chapter-10-03`集群中。这将在集群中的所有节点上加载镜像，以便我们在 Kubernetes 中创建部署时可以使用它。

示例应用程序中的`manifests`文件夹包含了在 Kubernetes 中配置应用程序的定义。请参考*第七章*，*在 WSL 中使用容器*，*在 Kubernetes 中运行 Web 应用程序*部分，其中有一个非常相似的应用程序的部署文件的演示和解释。我们可以使用`kubectl`将应用程序部署到 Kubernetes 中：

```
# kubectl apply -f manifests/
deployment.apps/chapter-10-example created
service/chapter-10-example created
```

在这里，我们使用`kubectl apply`命令和`-f`开关来传递要加载清单的路径。在这种情况下，我们指定`manifests`文件夹，以便`kubectl`将应用于文件夹中的所有文件。

我们的 Web 应用现在在`kind`集群中的一个节点上运行，并且我们刚刚应用的配置创建了一个 Kubernetes 服务来公开端口`5000`。这个服务只在`kind`集群内部可用，所以我们需要运行`kubectl port-forward`来将本地端口转发到该服务：

```
# kubectl port-forward service/chapter-10-example 5000
Forwarding from 127.0.0.1:5000 -> 5000
Forwarding from [::1]:5000 -> 5000
```

在输出中，您可以看到`kubectl port-forward`命令用于指定`service/chapter-10-03-example`服务作为目标，并将`5000`作为我们要转发的端口。这将设置从开发容器中的本地端口`5000`到在`kind`中运行的应用的服务的端口`5000`的端口转发。

如果您创建一个新的集成终端（通过点击集成终端右上角的加号符号），您可以使用它来运行`curl`命令来验证服务是否正在运行：

```
# curl localhost:5000
<html><body><h1>Hello from Linux (4.19.104-microsoft-standard) on chapter-10-example-99c88ff47-k7599</h1></body></html>
```

这个输出显示了从开发容器内部运行的`curl localhost:5000`命令，并使用`kubectl`端口转发访问在`kind`集群中部署的 Web 应用。

当我们在本章早些时候使用 Docker 处理应用程序时，我们在`devcontainer.json`中配置了`forwardPorts`属性来转发端口`5000`。这意味着 Visual Studio Code 已经设置好了将 Windows 上的端口`5000`转发到开发容器中的端口`5000`。任何发送到开发容器中端口`5000`的流量都将由我们刚刚运行的`kubectl`端口转发命令处理，并转发到 Kubernetes 服务上的端口`5000`。这意味着我们可以在 Windows 的浏览器中打开`http://localhost:5000`：

![图 10.7 - Windows 浏览器显示 Kubernetes 中的应用的截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_10.7_B16412.jpg)

图 10.7 - Windows 浏览器显示 Kubernetes 中的应用的截图

在这个截图中，我们可以看到 Windows 浏览器通过`http://localhost:5000`访问我们在 Kubernetes 中的应用。这是因为 Visual Studio Code 将 Windows 端口`5000`转发到开发容器内部的端口`5000`，这由`kubectl port-forward`处理，并转发到我们为应用部署的 Kubernetes 服务。

在本节中，我们使用了*Visual Studio Code*，*Remote-Containers*和*Docker*来创建一个容器化的开发环境，用于处理 Web 应用。我们看到了如何使用它来构建和运行我们的 Web 应用的容器镜像，然后创建一个 Kubernetes 集群，并在集群中部署和测试我们的应用，包括如何从主机 Windows 机器上的浏览器访问在 Kubernetes 中运行的 Web 应用。我们实现了所有这些，而不需要向主机机器添加任何其他要求，使得这个可移植的解决方案对于任何拥有 Visual Studio Code 和 Docker 的人来说都是快速上手的。

在本章的最后一节中，我们将介绍一些与开发容器一起工作的生产力技巧。

# 与开发容器一起工作的提示

在本节中，我们将介绍一些可以用来优化与开发容器一起工作体验的技巧。让我们从在构建完成后自动化开发容器内部的步骤开始。

## postCreateCommand 和自动化 pip 安装

在本章的早些示例中，我们在构建开发容器后需要运行`pip install`，并且每次在更改其配置后重新构建开发容器时都需要运行此命令。为了避免这种情况，可能会诱惑将`RUN`步骤添加到开发容器的 Dockerfile 中以执行`pip install`，但我更倾向于不将应用程序包放入开发容器镜像中。应用程序包依赖关系往往会随着时间的推移而发展，并且将它们构建到镜像中（并重新构建镜像以进行安装）会感觉有点笨重。随着时间的推移，在使用开发容器时，我的经验法则是在开发容器镜像中安装工具，并在运行时在开发容器内安装应用程序包。幸运的是，开发容器为我们提供了在`devcontainer.json`中配置`postCreateCommand`选项的功能：

```
// Use 'postCreateCommand' to run commands after the container is created.
"postCreateCommand": "pip3 install -r requirements.txt",
```

这个片段显示了将`postCreateCommand`配置为运行`pip install`步骤。在重新构建镜像后，Visual Studio Code 将在启动开发容器时自动运行`postCreateCommand`。

如果要运行多个命令，可以将它们组合为`command1 && command2`，或将它们放在一个脚本文件中，并从`postCreateCommand`运行该脚本。

当我们查看自动化开发容器任务的设置时，让我们再次关注端口转发。

## 端口转发

在本章的早些时候，我们利用了 Visual Studio Code 中的端口转发功能，将选定的流量从 Windows 主机转发到开发容器中，例如允许 Windows 浏览器连接到运行在开发容器中的 Web 应用程序。设置端口转发的一种方法是使用`devcontainer.json`文件：

```
// Use 'forwardPorts' to make a list of ports inside the container available locally.
"forwardPorts": [
    5000,
    5001
]
```

在这个片段中，我们在`forwardPorts`属性中指定了端口`5000`和`5001`。当 Visual Studio Code 启动开发容器时，它将自动开始转发这些端口，帮助我们平滑地进行工作流程。

要查看正在转发的端口，请切换到**REMOTE EXPLORER**视图（例如，通过运行**Remote Explorer: Focus on Forwarded Ports View**命令）：

![图 10.8 - 显示转发端口视图的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_10.8_B16412.jpg)

图 10.8 - 显示转发端口视图的屏幕截图

在这个屏幕截图中，您可以看到当前配置的转发端口列表。将鼠标悬停在端口上将显示屏幕截图中看到的地球和叉图标。单击地球将在默认的 Windows 浏览器中打开该端口，单击叉将停止共享该端口。

`forwardPorts`配置提高了生产力。

接下来，我们将重新讨论卷挂载的主题，并查看一些更多的示例。

## 挂载卷和 Bash 历史记录

在本章中，我们已经看到了几个配置挂载的示例，它们分为两个不同的类别：

+   将主机中的文件夹或文件挂载到容器中

+   将卷挂载到容器中以在容器实例之间保留数据

这两个类别中的第一个是将主机卷挂载到容器中，这是我们用来将主机 Docker 套接字（`/var/run/docker.sock`）挂载到开发容器中的方法。这也可以用于挂载诸如`~/.azure`之类的文件夹，从主机中将 Azure CLI 身份验证数据带入开发容器中，以避免在开发容器内再次登录。

第二类挂载创建了一个 Docker 卷，每次运行开发容器时都会挂载该卷。这在开发容器内提供了一个文件夹，其内容在容器重新构建时得以保留。这在处理包缓存文件时非常有用，如果您有大文件，您可以避免重复下载。另一个非常有用的例子是在开发容器中保留 Bash 历史记录。为此，我们可以在 Dockerfile 中配置`bash history`的位置：

```
# Set up bash history
RUN echo "export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" >> /root/.bashrc
```

此代码片段将配置添加到`.bashrc`文件（在 Bash 启动时运行），以配置`.bash_history`文件的位置为`/commandhistory`文件夹。单独使用它并没有太大作用，但如果将`/commandhistory`文件夹设置为挂载卷，结果就是在开发容器的实例之间保留 Bash 历史记录。实际上，这个配置还有一个额外的好处。如果没有开发容器，所有项目在主机上共享相同的 Bash 历史记录，因此如果您在几天内不使用某个项目，可能意味着与该项目相关的命令已从您的历史记录中删除。使用开发容器的这个配置，Bash 历史记录是特定于容器的，因此加载开发容器会恢复您的 Bash 历史记录，而不管您在主机上同时运行了哪些命令（确保为卷指定一个特定于项目的名称）。

这是一个说明所讨论的示例的配置：

```
"mounts": [
    // mount the host docker socket
    "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"
    // mount the .azure folder
    "source=${env:HOME}${env:USERPROFILE}/.azure,target=//root/.azure,type=bind",
// mount a volume for bash history
    "source=myproject-bashhistory,target=/commandhistory,type=volume",
],
```

此代码片段显示了我们在本节中讨论的各种挂载方式：

+   将主机的`/var/run/docker.sock`挂载到开发容器中以公开主机 Docker 套接字。

+   将主机的`.azure`文件夹挂载到开发容器中，以将缓存的 Azure CLI 身份验证带入开发容器。请注意，使用环境变量替换来定位源中的用户文件夹。

+   挂载卷以在开发容器实例之间保留 Bash 历史记录。

**挂载卷**是在使用开发容器时非常有用的工具，它可以通过允许我们将主机文件夹带入开发容器来大大提高生产力，以重用 Azure CLI 身份验证。它还可以在开发容器实例之间提供持久的文件存储，例如保留 Bash 历史记录或启用软件包缓存。

我们将看一下确保构建开发容器镜像的可重复性的最后一个提示。

## 使用固定版本的工具

在配置开发容器时，很容易（也很诱人）使用安装最新版本工具的命令。运行**Remote-Containers: Add Development Container Configuration Files…**命令时使用的起始开发容器定义通常使用安装最新版本工具的命令，而且很多工具的安装文档都指导您使用相同的命令。

如果您的开发容器 Dockerfile 中的命令安装最新版本的工具，那么您团队中的不同成员在其开发容器中可能会有不同版本的工具，这取决于他们构建开发容器的时间以及那时工具的最新版本是什么。此外，您可能会添加一个新工具并重新构建开发容器，并获取其他工具的更新版本。通常，工具在版本之间保持合理的兼容性水平，但偶尔会在版本之间更改其行为。这可能导致奇怪的情况，其中开发容器工具对一个开发人员有效，但对另一个开发人员无效，或者工具在重新构建开发容器（例如，添加新工具）之前工作正常，但然后无意中获取了其他工具的新版本。这可能会干扰您的工作流程，我通常更喜欢将工具固定到特定版本（例如本章中的`kind`和`kubectl`），然后在方便的时间或需要时明确更新它们的版本。

## 始终安装的扩展和 dotfiles

在设置开发容器时，您可以指定在创建开发容器时要安装的扩展。为此，您可以将以下内容添加到`devcontainer.json`中：

```
"extensions": [
    "redhat.vscode-yaml",
    "ms-vsliveshare.vsliveshare"
],
```

在这里，您可以在 JSON 中看到`extensions`属性，它指定了一个扩展 ID 的数组。要找到扩展的 ID，请在 Visual Studio Code 的**EXTENSIONS**视图中搜索扩展并打开它。您将看到以下详细信息：

![图 10.9 - 在 Visual Studio Code 中显示扩展信息的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_10.9_B16412.jpg)

图 10.9 - 显示 Visual Studio Code 中扩展信息的屏幕截图

在此屏幕截图中，您可以看到扩展 ID（`ms-vsliveshare.vsliveshare`）的信息被突出显示。通过在此处添加扩展，您可以确保任何使用开发容器的人都会安装相关的扩展。

Remote-Containers 扩展还具有一个名为**Always Installed Extensions**（或**Default Extensions**）的功能。此功能允许您配置一个在开发容器中始终要安装的扩展列表。要启用此功能，请选择**Preferences: Open user settings (JSON)**命令面板中的选项以打开设置 JSON 文件，并添加以下内容：

```
"remote.containers.defaultExtensions": [
    "mhutchie.git-graph",
    "trentrand.git-rebase-shortcuts"
],
```

在设置文件的这个片段中，您可以看到`remote.containers.defaultExtensions`属性。这是一个扩展 ID 数组，就像`devcontainer.json`中的`extensions`属性一样，但是在此处列出的扩展将始终安装在您在计算机上构建的开发容器中。

Remote-Containers 扩展支持的一个相关功能是`.bash_rc`和`.gitconfig`。要了解有关 dotfiles 的更多信息，请访问[`dotfiles.github.io/`](https://dotfiles.github.io/)。

Remote-Containers 中的 dotfile 支持允许您指定包含 dotfiles 的 Git 存储库的 URL，它们应该在开发容器中克隆到的位置以及克隆存储库后要运行的命令。这些可以在设置 JSON 中配置：

```
"remote.containers.dotfiles.repository": "stuartleeks/dotfiles",
"remote.containers.dotfiles.targetPath": "~/dotfiles",
"remote.containers.dotfiles.installCommand": "~/dotfiles/install.sh",
```

在这里，我们可以看到与我们刚刚描述的设置相对应的三个 JSON 属性。请注意，`remote.containers.dotfiles.repository`的值可以是完整的 URL，例如[`github.com/stuartleeks/dotfiles.git`](https://github.com/stuartleeks/dotfiles.git)，也可以是`stuartleeks/dotfiles`。

我喜欢使用 dotfiles 功能来设置 Bash 别名。我在计算机上的早期时间大部分都是在 MS-DOS 上度过的，我仍然发现我更容易输入`cls`和`md`这样的命令，而不是它们的等效命令`clear`和`mkdir`。使用 dotfiles 进行此配置有助于提高我在开发容器中的生产力，但是其他开发容器用户可能不需要或不想要这个配置。

有了 dotfiles 和**Always Installed Extensions**功能，现在需要做出一个决定：配置和扩展应该在开发容器定义中设置，还是使用 dotfiles 和**Always Installed Extensions**？为了回答这个问题，我们可以问自己扩展或设置是否是开发容器功能的核心部分或个人偏好。如果答案是个人偏好，那么我会将其放在 dotfiles 或**Always Installed Extensions**中。对于与开发容器的目的直接相关的功能，我会将其包含在开发容器定义中。

例如，如果我正在使用用于 Python 开发的开发容器，那么我会在开发容器定义中包含 Python 扩展。同样，对于使用 Kubernetes 的项目，我会在开发容器的 Dockerfile 中包含`kubectl`并为其配置 Bash 完成。我还会包含 RedHat YAML 扩展，以获得 Kubernetes YAML 文件的完成帮助（请参阅[`marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml`](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml)）。

无论是 dotfiles 还是**Always Installed Extensions**都可以是确保您的环境和开发容器体验熟悉和高效的好方法。

本节介绍了一些有助于提高开发容器生产力的提示，例如在重新构建开发容器后自动运行命令以及在开发容器启动时自动转发端口。

要了解有关配置开发容器的选项的更多信息，请参阅[`code.visualstudio.com/docs/remote/containers`](https://code.visualstudio.com/docs/remote/containers)。

# 概述

在本章中，您已经看到了 Visual Studio Code Remote-Containers 扩展如何允许我们使用标准的 Dockerfile 来定义一个容器来进行开发工作，同时保持 Visual Studio Code 的丰富交互环境。这些开发容器允许我们构建隔离的开发环境，以打包特定于项目的工具和依赖项，消除了通常在团队中同时协调工具更新的需要。此外，通过将开发容器定义包含在源代码控制中，团队成员可以轻松创建（和更新）开发环境。在处理 Web 应用程序时，您了解了如何将端口转发到在容器中运行的应用程序，以便您可以在 Windows 浏览器中浏览 Web 应用程序，同时在容器中进行交互式调试。

您还看到了如何通过共享主机 Docker 守护程序在开发容器中构建和使用容器化应用程序。本章考虑了从开发容器中使用 Kubernetes 的不同选项，并且您了解了如何在开发容器中配置`kind`以在主机机器上满足最低要求的 Kubernetes 环境。

最后，本章提供了一些有关使用开发容器的技巧。您了解了如何在创建开发容器后自动化步骤，以及如何在开发容器启动时自动转发端口。您还了解了如何从主机挂载文件夹或文件，以及如何创建持久化文件的卷，跨开发容器实例保留文件（例如，保留 Bash 历史记录或其他生成的数据）。所有这些方法都提供了使用开发容器简化开发流程的方式，帮助您专注于想要编写的代码。

使用 Remote-Containers 可能需要一些额外的思考来设置项目的开发环境，但它为个人和团队提供了一些引人注目的优势，包括隔离和可重复使用的开发环境。

在下一章中，我们将返回 WSL，并查看在 WSL 中使用命令行工具的各种技巧。


# 第十一章：命令行工具的生产力技巧

在本章中，我们将涵盖一些使用几种不同常见命令行工具的技巧。我们将首先看看如何提高在 WSL 中使用 Git 的生产力和改善体验。Git 被广泛使用，通过提高使用它进行源代码控制的任何项目的生产力，都会得到改善。之后，我们将看看 Azure 的`az`和 Kubernetes 的`kubectl`。对于这两个 CLI，我们将部署一个简单的示例资源，然后展示一些使用它们查询数据的技巧。与许多 CLI 一样，`az`和`kubectl`都提供了在`az`或`kubectl`中获取数据的选项，这些部分涵盖的技术可能与您正在使用的其他 CLI 相关。通过有效地学习如何操作 JSON，您可以打开使用各种 API 和 CLI 进行脚本编写和自动化的新可能性。

在本章中，我们将涵盖以下主要主题：

+   使用 Git

+   使用 JSON

+   使用 Azure CLI（`az`）

+   使用 Kubernetes CLI（`kubectl`）

让我们开始探索一些使用 Git 的技巧。

# 使用 Git

毫无疑问，Git 是一个常用的源代码控制系统。最初由 Linus Torvalds 编写用于 Linux 内核源代码，现在被广泛使用，包括微软等公司，它被广泛使用，包括用于 Windows 开发（有关更多信息，请参阅[`docs.microsoft.com/en-us/azure/devops/learn/devops-at-microsoft/use-git-microsoft`](https://docs.microsoft.com/en-us/azure/devops/learn/devops-at-microsoft/use-git-microsoft)）。

在本节中，我们将看一些在 WSL 中使用 Git 的技巧。一些技巧在之前的章节中已经涵盖，并提供了进一步的信息链接，而另一些是新技巧 - 这两者在这里都联系在一起，方便参考。

让我们从大多数命令行工具的快速胜利开始：bash 自动补全。

## Git 的 Bash 自动补全

在使用许多命令行工具时，bash 自动补全可以节省大量的输入时间，`git`也不例外。

例如，`git com<TAB>`将产生`git commit`，而`git chec<TAB>`将产生`git checkout`。如果你输入的部分命令不足以指定单个命令，那么 bash 自动补全似乎不会做任何事情，但按两次*Tab*将显示选项。举个例子：

```
$ git co<TAB><TAB>
commit   config
$ git co
```

在这里，我们看到`git co`可以完成为`git commit`或`git config`。

Bash 自动补全不仅仅是完成命令名称；你可以使用`git checkout my<TAB>`来完成分支名称为`git checkout my-branch`。

一旦你习惯了 bash 自动补全，你会发现它可以大大提高生产力！

接下来，让我们看看与远程 Git 仓库进行身份验证的选项。

## 使用 Git 进行身份验证

通过**Secure Shell**（**SSH**）密钥进行 Git 身份验证是一种强大的方法。这种身份验证方法重用 SSH 密钥，通常用于与远程机器建立 SSH 连接，以通过 Git 进行身份验证，并且受到主要的 Git 源代码控制提供者的支持。在*第五章*，*Linux 与 Windows 的互操作性*，在*SSH 代理转发*部分，我们看到如何配置 WSL 以重用存储在 Windows 中的 SSH 密钥。如果你已经设置了这个，它还可以让你在 WSL 中使用 SSH 密钥。

或者，如果您在 Windows 和 WSL 之间进行混合开发并希望在它们之间共享 Git 身份验证，则可能希望为 WSL 配置 Windows 的 Git 凭据管理器。这也支持在 GitHub 或 Bitbucket 等提供商上使用双因素身份验证（有关更多信息，请参见[`github.com/Microsoft/Git-Credential-Manager-for-Windows`](https://github.com/Microsoft/Git-Credential-Manager-for-Windows)）。要使用此功能，您必须在 Windows 中安装 Git。要配置，请从您的**distribution**（**distro**）运行以下命令：

```
git config --global credential.helper "/mnt/c/Program\ Files/Git/mingw64/libexec/git-core/git-credential-manager.exe"
```

此命令将 Git 配置为启动 Git Credential Manager for Windows 来处理与远程存储库的身份验证。通过 Windows 访问 Git 远程存储库存储的任何凭据将被 WSL 重用（反之亦然）。有关更多详细信息，请参见[`docs.microsoft.com/en-us/windows/wsl/tutorials/wsl-git#git-credential-manager-setup`](https://docs.microsoft.com/en-us/windows/wsl/tutorials/wsl-git#git-credential-manager-setup)。

认证问题解决后，让我们看一下在 Git 中查看历史的几个选项。

## 查看 Git 历史

在 WSL 中使用 Git 时，有许多不同的方法可以查看 Git 存储库中提交的历史记录。在这里，我们将看看以下不同的选项：

+   使用`git` CLI

+   使用 Windows 的图形 Git 工具

+   使用 Visual Studio Code Remote-WSL

第一个选项是在 CLI 中使用`git log`命令：

```
$ git log --graph --oneline --decorate --all
* 35413d8 (do-something) Add goodbye
| * 44da775 (HEAD -> main) Fix typo
| * c6d17a3 Add to hello
|/
* 85672d8 Initial commit
```

在`git log`的输出中，您可以看到使用一些附加开关运行`git log`命令产生了简洁的输出，使用文本艺术来显示分支。这种方法很方便，因为它可以直接从 WSL 的命令行中使用，并且除了 WSL 中安装的 Git 之外不需要安装任何东西。但是，这个命令可能有点繁琐，所以您可能希望创建一个 Git 别名，如下所示：

```
$ git config --global --replace-all alias.logtree 'log --graph --oneline --decorate --all'
```

在这里，我们使用`git config`命令为先前的 Git 命令创建了一个名为`logtree`的别名。创建后，我们现在可以运行`git logtree`来生成先前的输出。

如果您在 Windows 上使用 Git 的图形工具，您可以将其指向 WSL 中的 Git 存储库。在第九章《Visual Studio Code 和 WSL》的《查看 Git 历史》部分中，我们看到了如何使用 Git 附带的`gitk`实用程序。例如，我们可以从 WSL shell 中的 Git 存储库文件夹运行`gitk.exe --all`来启动 Windows 的`gitk.exe`可执行文件：

![图 11.1 - 显示 Windows 中 gitk 实用程序的屏幕截图，显示了 WSL Git 存储库](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_11.1_B16412.jpg)

图 11.1 - 显示 Windows 中 gitk 实用程序的屏幕截图，显示了 WSL Git 存储库

在这个屏幕截图中，我们可以看到`gitk`实用程序在 Windows 中运行，并显示了之前使用`git log`看到的相同的 Git 存储库。因为我们是从 WSL 的 shell 中启动它的，它捕获了`\\wsl$`共享，用于从 Windows 访问 WSL 中的 shell 当前文件夹（有关`\\wsl$`共享的更多信息，请参见第四章《Windows 到 Linux 的互操作性》，《从 Windows 访问 Linux 文件》部分）。这种方法的一个潜在问题是通过`\\wsl$`共享访问文件会有性能开销，对于大型 Git 存储库，这可能会使 Windows 的 Git 工具加载缓慢。

我们在第九章《Visual Studio Code 和 WSL》的《查看 Git 历史》部分中看到的另一个选项是使用 Visual Studio Code。通过使用 Remote-WSL 扩展，我们可以安装其他扩展程序，使它们实际在 WSL 中运行。**Git Graph 扩展程序**是 Visual Studio Code 的一个方便的补充，允许您以图形方式查看 Git 历史，并且与 Remote-WSL 配合良好。您可以在这里看到一个例子：

![图 11.2 - 显示 Visual Studio Code 中 Git Graph 扩展程序的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_11.2_B16412.jpg)

图 11.2 – 显示 Visual Studio Code 中的 Git Graph 扩展的屏幕截图

这个屏幕截图再次显示了相同的 Git 存储库，但这次是在 Visual Studio Code 中使用 Git Graph 扩展。由于这个扩展是通过 Remote-WSL 在 WSL 中加载的，所有对 Git 存储库的访问都是直接在 WSL 中执行的，而不会通过 `\\wsl$` 共享进行查询时的性能开销。

在这里我们看到了一些方法，每种方法都有其自身的好处，在各自的上下文中都很有用。*Git CLI* 方法在你已经在终端时很方便，并且它在 WSL 中运行，因此性能很好。对于检查复杂的分支和历史记录，图形工具往往是最好的选择。然而，正如前面提到的，从 Windows 使用图形 Git 工具会产生 `\\wsl$` 共享的性能开销 – 通常情况下这是不明显的，但对于文件或历史记录很多的 Git 存储库来说，它可能开始变得更加显著。在这些情况下，或者当我已经在编辑器中工作时，我发现 Visual Studio Code 的 Git Graph 等扩展非常有用，它提供了图形化的可视化，而没有性能开销。

接下来，我们将看看在使用 Git 时改进我们的 bash 提示。

## bash 提示中的 Git 信息

在 Git 存储库中的文件夹中使用 bash 时，默认提示不会给出有关 Git 存储库状态的任何提示。有各种选项可以将 Git 存储库的上下文添加到 bash 中，我们将在这里看一些选项。第一个选项是 **bash-git-prompt** (https://github.com/magicmonty/bash-git-prompt)，它在 Git 存储库中自定义了你的 bash 提示。你可以在这里看到一个例子：

![图 11.3 – 显示 bash-git-prompt 的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_11.3_B16412.jpg)

图 11.3 – 显示 bash-git-prompt 的屏幕截图

正如这个屏幕截图所示，`bash-git-prompt` 显示了你当前所在的分支（在这个例子中是 `main`）。它还指示了你的本地分支是否有提交要推送，或者是否有要从远程分支拉取的提交，通过上下箭头来表示。上箭头表示有提交要推送，下箭头表示有提交要拉取。最后，它显示了你是否有未提交的本地更改 – 在这个例子中是 `+1`。

要安装 `bash-git-prompt`，首先使用以下命令克隆存储库：

```
git clone https://github.com/magicmonty/bash-git-prompt.git ~/.bash-git-prompt --depth=1
```

这个 `git clone` 命令将存储库克隆到用户文件夹中的 `.bash-git-prompt` 文件夹中，并使用 `--depth=1` 仅拉取最新的提交。

接下来，在你的用户文件夹中的 `.bashrc` 中添加以下内容：

```
if [ -f "$HOME/.bash-git-prompt/gitprompt.sh" ]; then
    GIT_PROMPT_ONLY_IN_REPO=1
    source $HOME/.bash-git-prompt/gitprompt.sh
fi
```

这个片段将 `GIT_PROMPT_ONLY_IN_REPO` 变量设置为仅在带有 Git 存储库的文件夹中使用自定义提示，然后加载 `git` 提示。现在，重新打开你的终端并切换到一个 Git 存储库的文件夹中，看看 `bash-git-prompt` 的效果。有关其他配置选项，请参阅 [`github.com/magicmonty/bash-git-prompt`](https://github.com/magicmonty/bash-git-prompt) 上的文档。

丰富你的 bash 提示的另一个选项是 `bash-git-prompt`，它接管了你的一般提示体验，为提示添加了 Git 和 Kubernetes 等内容。在下面的屏幕截图中可以看到 Powerline 提示的一个例子：

![图 11.4 – 显示 Powerline 提示的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_11.4_B16412.jpg)

图 11.4 – 显示 Powerline 提示的屏幕截图

正如这个屏幕截图所示，Powerline 使用了一些特殊的字体字符，并非所有字体都设置了这些字符，所以第一步是确保我们有一个合适的字体。Windows 终端附带了一个名为 `CascadiaCodePL.ttf` 和 `CascadiaMonoPL.ttf` 的字体，可以通过在 **Windows Explorer** 中右键单击 `ttf` 文件夹中的文件并选择 **安装** 来安装。

安装了 Powerline 字体后，我们需要配置终端来使用它。如果你正在使用 Windows 终端，那么启动它并按下 *Ctrl* + *,* 加载设置，并添加以下内容：

```
"profiles": {
    "defaults": {
        "fontFace": "Cascadia Mono PL"
    },
```

在这里，我们将默认的`fontFace`值设置为我们刚安装的`Cascadia Mono PL`（Powerline）字体。要更改单个配置文件的字体，请参见*第三章*，*开始使用 Windows 终端*，*更改字体*部分。

现在我们已经设置了一个带有 Powerline 字体的终端，我们可以安装 Powerline。有几种变体，我们将使用来自[`github.com/justjanne/powerline-go/releases`](https://github.com/justjanne/powerline-go/releases)的`powerline-go-linux-amd64`版本，并将其保存为`powerline-go`，放在 WSL 发行版的`PATH`中的某个位置，例如`/usr/local/bin`。（另一种选择是通过**Go**安装，但发行版存储库可能停留在旧版本的 Go 上，导致不兼容-如果您更喜欢尝试此选项，请参考 Windows 终端文档：[`docs.microsoft.com/en-us/windows/terminal/tutorials/powerline-setup`](https://docs.microsoft.com/en-us/windows/terminal/tutorials/powerline-setup)。）

安装了`powerline-go`后，我们可以通过将以下内容添加到`bashrc`来配置 bash 使用它：

```
function _update_ps1() {
    PS1="$(powerline-go -error $?)"
}
if [ "$TERM" != "linux" ] && [ "$(command -v powerline-go > /dev/null 2>&1; echo $?)" == "0" ]; then
    PROMPT_COMMAND="_update_ps1; $PROMPT_COMMAND"
fi
```

在这里，我们创建了一个`_update_ps1`函数，调用了`powerline-go`。这是添加额外开关以控制`powerline-go`行为的地方-有关更多详细信息，请参阅文档：[`github.com/justjanne/powerline-go#customization`](https://github.com/justjanne/powerline-go#customization)。

在使用 Git 时，调整提示以自动获取 Git 仓库的上下文可以使您更轻松地选择任何选项。将此与在 Git 中设置身份验证以在 Windows 和 WSL 之间共享，并了解在不同情况下如何最好地查看 Git 历史记录相结合，您将能够在 WSL 中高效地使用 Git。

在下一节中，我们将看一下几种处理 JSON 数据的方法。

# 处理 JSON

自动化复杂任务可以节省数小时的手动劳动。在本节中，我们将探讨一些处理 JSON 数据的技术，这是许多命令行工具和 API 允许您使用的常见格式。在本章后面，我们将展示一些示例，说明您可以如何使用这些技术轻松地创建和发布内容到云网站或 Kubernetes 集群。

对于本节，书籍的附带代码中有一个示例 JSON 文件。您可以使用 Git 从[`github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques`](https://github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques)克隆此代码。示例 JSON 名为`wsl-book.json`，位于`chapter-11/02-working-with-json`文件夹中，基于一本书的章节和标题的 JSON 描述。此处显示了此 JSON 的片段：

```
{
    "title": "WSL: Tips, Tricks and Techniques",
    "parts": [
        {
            "name": "Part 1: Introduction, Installation and Configuration",
            "chapters": [
                {
                    "title": "Introduction to the Windows Subsystem for Linux",
                    "headings": [
                        "What is the Windows Subsystem for Linux?",
                        "Exploring the Differences between WSL 1 and 2"
                    ]
                },
			...
            "name": "Part 2: Windows and Linux - A Winning Combination",
            "chapters": [
                {
			...
```

此片段显示了示例 JSON 的结构。值得花一些时间熟悉它，因为它是本节示例的基础。本节中的示例假定您在包含示例 JSON 的文件夹中打开了一个 shell。

让我们开始使用一个流行的实用程序`jq`。

## 使用 jq

我们将首先看一下`jq`，它是一个非常方便的用于处理 JSON 字符串的实用程序，并且在主要平台上都受支持。完整的安装选项列在[`stedolan.github.io/jq/download/`](https://stedolan.github.io/jq/download/)上，但您可以通过在 Debian/Ubuntu 上运行`sudo apt-get install jq`来快速开始。

在其最基本的形式中，`jq`可用于格式化输入。例如，我们可以将 JSON 字符串传输到`jq`中：

```
$ echo '[1,2,"testing"]' | jq
[
  1,
  2,
  "testing"
]
```

在这个命令的输出中，你可以看到`jq`已经将紧凑的 JSON 输入转换成了格式良好的输出。当与返回紧凑 JSON 的 API 进行交互时，这个功能本身就很有用。然而，`jq`真正的威力在于它的查询能力，我们将在本节中探讨这些能力。作为一个可以实现的预演，看一下下面的例子：

```
$ cat ./wsl-book.json | jq ".parts[].name"
"Part 1: Introduction, Installation and Configuration"
"Part 2: Windows and Linux - A Winning Combination"
"Part 3: Developing with Windows Subsystem for Linux"
```

这个输出显示了`jq`提取和输出样本 JSON 中部件的`name`值。当使用返回 JSON 数据的 API 和命令行工具进行脚本编写时，这种能力非常有用，我们将从一些简单的查询开始，逐渐发展到更复杂的查询。你可以使用`jq` CLI 或者在[`jqplay.org`](https://jqplay.org)上使用**jq playground**来跟随这些例子，就像在这里的截图中看到的那样。

![图 11.5 - 展示 jq playground 的截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_11.5_B16412.jpg)

图 11.5 - 展示 jq playground 的截图

这个截图显示了在`jq` playground 中打开的前面的例子。在左上角，你可以看到过滤器（`.parts[].name`），在下面是输入的 JSON，右边是`jq`的输出。当你在处理复杂的查询时，playground 可以是一个有用的环境，底部的**命令行**部分甚至会给出你可以复制并在脚本中使用的命令行。

现在你已经知道`jq`可以做什么了，让我们从一个简单的查询开始。我们要处理的 JSON 有两个顶级属性：`title`和`parts`。如果我们想提取`title`属性的值，我们可以使用以下查询：

```
$ cat ./wsl-book.json | jq ".title"
"WSL: Tips, Tricks and Techniques"
```

在这里，我们使用了`.title`过滤器来提取`title`属性的值。注意输出中的值被引号引起来，因为`jq`默认输出 JSON。在脚本中将这个值赋给一个变量时，通常希望得到没有引号的值，我们可以使用`jq`的`-r`选项来获得原始输出：

```
$ BOOK_TITLE=$(cat ./wsl-book.json | jq ".title" -r)
$ echo $BOOK_TITLE
WSL: Tips, Tricks and Techniques
```

这个输出显示了使用`-r`选项来获得原始（未引用）输出并将其赋给一个变量。

在这个例子中，我们使用了`title`属性，它是一个简单的字符串值。另一个顶级属性是`parts`，它是一个 JSON 对象的数组：

```
$ cat ./wsl-book.json | jq ".parts"
[
  {
    "name": "Part 1: Introduction, Installation and Configuration",
    "chapters": [
      {
        "title": "Introduction to the Windows Subsystem for Linux",
        "headings": [
          "What is the Windows Subsystem for Linux?",
          "Exploring the Differences between WSL 1 and 2"
        ]
      },
	...
```

在这个命令的输出中，我们看到检索`parts`属性返回了属性的完整值。我们可以将过滤器更改为`.parts[0]`来获取`parts`数组中的第一个项目，然后进一步扩展过滤器，如果我们想要获取第一个部件的名称，就像这样：

```
$ cat ./wsl-book.json | jq ".parts[0].name"
"Part 1: Introduction, Installation and Configuration"
```

在这里，我们看到了如何构建一个查询来沿着 JSON 数据的层次结构进行选择属性和索引数组以选择特定的值。有时候能够获得一个数据列表是很有用的 - 例如，获取所有部件的名称。我们可以使用以下命令来实现：

```
$ cat ./wsl-book.json | jq ".parts[].name"
"Part 1: Introduction, Installation and Configuration"
"Part 2: Windows and Linux - A Winning Combination"
"Part 3: Developing with Windows Subsystem for Linux"
```

正如你在这个例子中看到的，我们省略了前一个过滤器中的数组索引，`jq`已经处理了剩下的过滤器（`.name`）并针对`parts`数组的每个项目进行了处理。与单一值输出一样，我们可以添加`-r`选项，以便在脚本中更容易地处理输出的未引用字符串。或者，如果我们正在处理 API，我们可能希望构建 JSON 输出 - 例如，要将前面的值输出为数组，我们可以将过滤器包装在方括号中：`[.parts[].name]`。

到目前为止，我们只使用了一个单一的过滤表达式，但是`jq`允许我们将多个过滤器链接在一起，并将一个过滤器的输出作为下一个过滤器的输入。例如，我们可以将`.parts[].name`重写为`.parts[] | .name`，这将产生相同的输出。从这里，我们可以将第二个过滤器改为`{name}`，以产生一个带有`name`属性的对象，而不仅仅是名称值：

```
$ cat ./wsl-book.json | jq '.parts[] | {name}'
{
  "name": "Part 1: Introduction, Installation and Configuration"
}
{
  "name": "Part 2: Windows and Linux - A Winning Combination"
}
{
  "name": "Part 3: Developing with Windows Subsystem for Linux"
}
```

在这里，我们看到`.parts`数组中的每个值现在都产生了输出中的一个对象，而不仅仅是之前的简单字符串。`{name}`语法实际上是`{name: .name}`的简写。完整的语法使您更容易看到如何控制输出中的属性名称 - 例如，`{part_name: .name}`。使用完整的语法，我们还可以看到属性值是另一个过滤器。在这个例子中，我们使用了简单的`.name`过滤器，但我们也可以使用更丰富的过滤器来构建：

```
$ cat ./wsl-book.json | jq '.parts[] | {name: .name, chapter_count: .chapters | length}'
{
  "name": "Part 1: Introduction, Installation and Configuration",
  "chapter_count": 3
}
{
  "name": "Part 2: Windows and Linux - A Winning Combination",
  "chapter_count": 5
}
{
  "name": "Part 3: Developing with Windows Subsystem for Linux",
  "chapter_count": 3
}
```

在这个例子中，我们添加了`.chapters | length`作为一个过滤器来指定`chapter_count`属性的值。`.chapters`表达式被应用于当前正在处理的`parts`数组的值，并选择`chapters`数组，然后将其解析为`length`函数，该函数返回数组长度。有关`jq`中可用函数的更多信息，请查看 https://stedolan.github.io/jq/manual/#Builtinoperatorsandfunctions 上的文档。

作为`jq`的最后一个例子，让我们汇总一下部分的摘要，显示部分名称以及章节标题的列表：

```
$ cat ./wsl-book.json | jq '[.parts[] | {name: .name, chapters: [.chapters[] | .title]}]'
[
  {
    "name": "Part 1: Introduction, Installation and Configuration",
    "chapters": [
      "Introduction to the Windows Subsystem for Linux",
      "Installing and Configuring the Windows Subsystem for Linux",
      "Getting Started with Windows Terminal"
    ]
  },
  {
    "name": "Part 2: Windows and Linux - A Winning Combination",
    "chapters": [
...
]
```

在这个例子中，`parts`数组被传递到一个过滤器中，该过滤器为每个数组项创建一个带有`name`和`chapters`属性的对象。`chapters`属性是通过将`chapters`数组传递到`title`属性的选择器中，然后将其包装在一个数组中来构建的：`[.chapters[] | title]`。整个结果再次被包装在一个数组中（再次使用方括号）以在输出中创建这些摘要对象的 JSON 数组。

提示

有各种方法可以使用命令行工具（如`jq`）查找选项。您可以运行`jq --help`获取简要的帮助页面，或者运行`man jq`查看完整的 man 页面。这些的一个方便的替代品是`tldr`（有关更多详细信息和安装说明，请参见[`tldr.sh`](https://tldr.sh)）。`tldr`实用程序将自己描述为*简化和社区驱动的 man 页面*，运行`tldr jq`将提供比 man 页面更短的输出，并包含有用的示例。

这次风风火火的旅行向您展示了`jq`提供的一些功能，无论是在与 JSON 交互式工作时格式化 JSON 输出以便阅读，还是快速选择 JSON 中的单个值以在脚本中使用，或者将 JSON 输入转换为新的 JSON 文档时。在处理 JSON 时，`jq`是一个非常有用的工具，我们将在本章的后续部分中看到更多这方面的例子。

在下一节中，我们将探索使用**PowerShell**处理 JSON 数据的选项。

## 使用 PowerShell 处理 JSON

在本节中，我们将探讨 PowerShell 为我们提供的一些处理 JSON 数据的能力。PowerShell 是一个起源于 Windows 但现在可用于 Windows、Linux 和 macOS 的 shell 和脚本语言。要在 WSL 中安装，请按照您的发行版的安装说明进行安装，网址为 https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7。例如，对于 Ubuntu 18.04，我们可以使用以下命令安装 PowerShell：

```
# Download the Microsoft repository GPG keys wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb
# Register the Microsoft repository GPG keys sudo dpkg -i packages-microsoft-prod.deb
# Update the list of products sudo apt-get update
# Enable the "universe" repositories sudo add-apt-repository universe
# Install PowerShell sudo apt-get install -y powershell
```

这些步骤将注册 Microsoft 软件包存储库，然后从那里安装 PowerShell。安装完成后，您可以通过运行`pwsh`来启动 PowerShell，这将为您提供一个交互式的 shell，我们将在本节的其余示例中使用它。

我们可以按如下方式加载和解析示例 JSON 文件：

```
PS > Get-Content ./wsl-book.json | ConvertFrom-Json
title                            parts
-----                            -----
WSL: Tips, Tricks and Techniques {@{name=Part 1: Introduction, Installation and Configuration; chapters=System.Object[…
```

在这里，我们看到了`Get-Content` cmdlet（PowerShell 中的命令称为`ConvertFrom-Json`用于将 JSON 对象图解析为 PowerShell 对象。在这一点上，我们可以使用任何用于处理数据的 PowerShell 功能。例如，我们可以使用`Select-Object` cmdlet 获取标题：

```
PS > Get-Content ./wsl-book.json | ConvertFrom-Json | Select-Object -ExpandProperty title
WSL: Tips, Tricks and Techniques
```

`Select-Object`命令允许我们对一组对象执行各种操作，例如从集合的开头或结尾获取指定数量的项目，或者仅筛选唯一的项目。在这个例子中，我们使用它来选择要输出的输入对象的属性。获取标题的另一种方法是直接使用转换后的 JSON 对象，如下面的命令所示：

```
PS > $data = Get-Content ./wsl-book.json | ConvertFrom-Json
PS > $data.title
WSL: Tips, Tricks and Techniques
```

在这个例子中，我们保存了将数据从 JSON 转换为`$data`变量的结果，然后直接访问了`title`属性。现在我们有了`$data`变量，我们可以探索`parts`属性：

```
PS > $data.parts | Select-Object -ExpandProperty name
Part 1: Introduction, Installation and Configuration
Part 2: Windows and Linux - A Winning Combination
Part 3: Developing with Windows Subsystem for Linux
```

在这个例子中，我们直接访问`parts`属性，这是一个对象数组。然后我们将这个对象数组传递给`Select-Object`来展开每个部分的`name`属性。如果我们想生成 JSON 输出（就像在上一节中使用`jq`一样），我们可以使用`ConvertTo-Json`命令：

```
PS > $data.parts | select -ExpandProperty name | ConvertTo-Json
[
  "Part 1: Introduction, Installation and Configuration",
  "Part 2: Windows and Linux - A Winning Combination",
  "Part 3: Developing with Windows Subsystem for Linux"
]
```

在这里，我们使用了与上一个示例中相同的命令（尽管我们使用了`select`别名作为`Select-Object`的简洁形式），然后将输出传递给`ConvertTo-Json`命令。这个命令执行与`ConvertFrom-Json`相反的操作-换句话说，它将一组 PowerShell 对象转换为 JSON。

如果我们想要输出带有部分名称的 JSON 对象，可以使用以下命令：

```
PS > $data.parts | ForEach-Object { @{ "Name" = $_.name } } | ConvertTo-Json
[
  {
    "Name": "Part 1: Introduction, Installation and Configuration"
  },
  {
    "Name": "Part 2: Windows and Linux - A Winning Combination"
  },
  {
    "Name": "Part 3: Developing with Windows Subsystem for Linux"
  }
]
```

在这里，我们使用`ForEach-Object`而不是`Select-Object`。`ForEach-Object`命令允许我们为输入数据中的每个对象提供一个 PowerShell 片段，并且`$_`变量包含每次执行的集合中的项目。在`ForEach-Object`内部的片段中，我们使用`@{ }`语法创建一个名为`Name`的新 PowerShell 对象属性，该属性设置为当前输入对象的`name`属性（在这种情况下是部分名称）。最后，我们将生成的对象集传递给`ConvertTo-Json`以转换为 JSON 输出。

我们可以使用这种方法来构建更丰富的输出-例如，包括部分名称以及它包含的章节数：

```
PS > $data.parts | ForEach-Object { @{ "Name" = $_.name; "ChapterCount"=$_.chapters.Count } } | ConvertTo-Json
[
  {
    "ChapterCount": 3,
    "Name": "Part 1: Introduction, Installation and Configuration"
  },
  {
    "ChapterCount": 5,
    "Name": "Part 2: Windows and Linux - A Winning Combination"
  },
  {
    "ChapterCount": 3,
    "Name": "Part 3: Developing with Windows Subsystem for Linux"
  }
]
```

在这个例子中，我们扩展了`ForEach-Object`内部的片段到`@{ "Name" = $_.name; "ChapterCount"=$_.chapters.Count }`。这将创建一个具有两个属性的对象：`Name`和`ChapterCount`。`chapters`属性是一个 PowerShell 数组，因此我们可以使用数组的`Count`属性作为输出中`ChapterCount`属性的值。

如果我们想要输出每个部分的章节名称的摘要，我们可以结合我们迄今为止看到的方法：

```
PS > $data.parts | ForEach-Object { @{ "Name" = $_.name; "Chapters"=$_.chapters | Select-Object -ExpandProperty title } } | ConvertTo-Json
[
  {
    "Chapters": [
      "Introduction to the Windows Subsystem for Linux",
      "Installing and Configuring the Windows Subsystem for Linux",
      "Getting Started with Windows Terminal"
    ],
    "Name": "Part 1: Introduction, Installation and Configuration"
  },
  {
    "Chapters": [
...
    ],
    "Name": "Part 2: Windows and Linux - A Winning Combination"
  },
  ...
]
```

在这里，我们再次使用`ForEach-Object`命令来创建 PowerShell 对象，这次使用`Name`和`Chapters`属性。要创建`Chapters`属性，我们只需获取每个章节的名称，我们可以像在本节前面选择部分名称时一样使用`Select-Object`命令，但这次我们将其用在`ForEach-Object`片段内。能够以这种方式组合命令使我们具有很大的灵活性。

在之前的例子中，我们一直在处理使用`Get-Content`从本地文件加载的数据。要从 URL 下载数据，PowerShell 提供了一些方便的命令：`Invoke-WebRequest`和`Invoke-RestMethod`。

我们可以使用`Invoke-WebRequest`从 GitHub 下载示例数据：

```
$SAMPLE_URL="https://raw.githubusercontent.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques/main/chapter-11/02-working-with-json/wsl-book.json"
PS > Invoke-WebRequest $SAMPLE_URL
StatusCode        : 200
StatusDescription : OK
Content           : {
                        "title": "WSL: Tips, Tricks and Techniques",
                        "parts": [
                            {
                                "name": "Part 1: Introduction, Installation and Configuration",
                                "chapters": [
                                    {
                        …
RawContent        : HTTP/1.1 200 OK
                    Connection: keep-alive
                    Cache-Control: max-age=300
                    Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox
                    ETag: "075af59ea4d9e05e6efa0b4375b3da2f8010924311d487d…
Headers           : {[Connection, System.String[]], [Cache-Control, System.String[]], [Content-Security-Policy, System.String[]], [ETag, System.Strin                     g[]]…}
Images            : {}
InputFields       : {}
Links             : {}
RawContentLength  : 4825
RelationLink      : {}
```

在这里，我们看到`Invoke-WebRequest`使我们可以访问响应的各种属性，包括状态代码和内容。要将数据加载为 JSON，我们可以将`Content`属性传递给`ConvertFrom-JSON`：

```
PS > (iwr $SAMPLE_URL).Content | ConvertFrom-Json
                                                                                                                                                     title                           parts
-----                            -----
WSL: Tips, Tricks and Techniques {@{name=Part 1: Introduction, Installation and Configuration; chapters=System.Object[]}, @{name=Part 2: Windows and…
```

在这个例子中，我们使用了`iwr`别名作为`Invoke-WebRequest`的简写，这在交互式工作时可能很方便。我们本可以将`Invoke-WebRequest`的输出传递给`Select-Object`来展开`Content`属性，就像我们之前看到的那样。相反，我们将表达式括在括号中，直接访问属性以显示另一种语法。然后将此内容传递给`ConvertFrom-Json`，将数据转换为 PowerShell 对象，就像我们之前看到的那样。这种可组合性很方便，但如果您只对 JSON 内容感兴趣（而不关心响应的其他属性），那么您可以使用`Invoke-RestMethod`命令来实现这一点：

```
PS > Invoke-RestMethod $SAMPLE_URL
title                            parts
-----                            -----
WSL: Tips, Tricks and Techniques {@{name=Part 1: Introduction, Installation and Configuration; chapters=System.Object[]}, @{name=Part 2: Windows and…
```

在这里，我们看到与之前相同的输出，因为`Invoke-RestMethod`命令已经确定响应包含 JSON 数据，并自动执行了转换。

## 总结使用 JSON

在最后两节中，您已经看到了`jq`和 PowerShell 如何为您提供处理 JSON 输入的丰富功能。在每种情况下，您已经看到如何提取简单的值，并执行更复杂的操作以生成新的 JSON 输出。由于 JSON 在 API 和 CLI 中被广泛使用，能够有效地处理 JSON 是一个巨大的生产力提升，正如我们将在本章的其余部分中看到的那样。在本章的其余部分，我们将在需要额外工具来处理 JSON 的示例中使用`jq`，但请注意，您也可以使用 PowerShell 来实现这一点。

在下一节中，我们将看到如何将处理 JSON 的技术与另一个命令行工具结合使用，这次是一些处理 Azure CLI 的技巧。

# 使用 Azure CLI（az）

云计算的推动带来了许多好处，其中包括能够按需创建计算资源的能力。能够自动化创建、配置和删除这些资源是利益的关键部分，这通常是使用相关云供应商提供的 CLI 来执行的。

在本节中，我们将从命令行创建和发布一个简单的网站，并将其作为查看使用 Azure CLI（az）的一些技巧的方式。我们将看到如何使用本章前面看到的`jq`以及`az`的内置查询功能。如果您想跟着做，但还没有 Azure 订阅，您可以在 https://azure.microsoft.com/free/免费试用。让我们开始安装 CLI。

## 安装和配置 Azure CLI

安装 Azure CLI 有多种选项。最简单的方法是在您想要安装 CLI 的 WSL 分发中打开终端，并运行以下命令：

```
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

此命令下载安装脚本并在 bash 中运行。如果您不想直接从互联网运行脚本，您可以先下载脚本并检查它，或者在这里查看单独的安装步骤：[`docs.microsoft.com/en-us/cli/azure/install-azure-cli-apt?view=azure-cli-latest`](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-apt?view=azure-cli-latest)。

安装完成后，您应该能够从终端运行`az`。要连接到您的 Azure 订阅，以便管理它，请运行`az login`：

```
$ az login
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code D3SUM9QVS to authenticate.
```

在`az login`命令的输出中，您可以看到`az`生成了一个代码，我们可以通过访问[`microsoft.com/devicelogin`](https://microsoft.com/devicelogin)来使用该代码登录。在浏览器中打开此网址，并使用您用于 Azure 订阅的帐户登录。在这样做后不久，`az login`命令将输出您的订阅信息并完成运行。

如果您有多个订阅，可以使用`az account list`列出它们，并使用`az account set --subscription YourSubscriptionNameOrId`选择要使用的默认订阅。

现在我们已经登录，可以开始运行命令了。在 Azure 中，资源存放在资源组（逻辑容器）中，所以让我们列出我们的组：

```
$ az group list
[]
```

在这里，命令的输出显示订阅中当前没有资源组。请注意，输出是`[]` - 一个空的 JSON 数组。默认情况下，`az`将结果输出为 JSON，因此对具有一些现有资源组的订阅运行先前的命令会给我们以下输出：

```
$ az group list
[
  {
    "id": "/subscriptions/36ce814f-1b29-4695-9bde-1e2ad14bda0f/resourceGroups/wsltipssite",
    "location": "northeurope",
    "managedBy": null,
    "name": "wsltipssite",
    "properties": {
      "provisioningState": "Succeeded"
    },
    "tags": null,
    "type": "Microsoft.Resources/resourceGroups"
  },
  ...
]
```

前面的输出已经被截断，因为它变得非常冗长。幸运的是，`az`允许我们从多种输出格式中进行选择，包括表格：

```
$ az group list -o table
Name         Location     Status
-----------  -----------  ---------
wsltipssite  northeurope  Succeeded
wsltipstest  northeurope  Succeeded
```

在这个输出中，我们使用了`-o table`开关来配置表格输出。这种输出格式更简洁，通常对 CLI 的交互使用非常方便，但是不得不不断地在命令中添加开关可能会很繁琐。幸运的是，我们可以通过运行`az configure`命令将表格输出设置为默认值。这将为您提供一组简短的交互选择，包括默认使用的输出格式。由于默认输出格式可以被覆盖，因此在脚本中指定 JSON 输出是很重要的，以防用户配置了不同的默认值。

有关使用`az`的更多示例，包括如何在 Azure 中创建各种资源，请参阅[`docs.microsoft.com/cli/azure`](https://docs.microsoft.com/cli/azure)上的*示例*部分。在本节的其余部分，我们将看一些关于使用 CLI 查询有关资源信息的具体示例。

## 创建 Azure Web 应用程序

为了演示使用`az`进行查询，我们将创建一个简单的 Azure Web 应用程序。Azure Web 应用程序允许您托管用各种语言编写的 Web 应用程序（包括.NET、Node.js、PHP、Java 和 Python），并且有许多部署选项可供您根据自己的喜好选择。为了确保我们专注于 CLI 的使用，我们将保持简单，创建一个单页面静态网站，并通过 FTP 部署它。要了解更多关于 Azure Web 应用程序的信息，请参阅[`docs.microsoft.com/en-us/azure/app-service/overview`](https://docs.microsoft.com/en-us/azure/app-service/overview)上的文档。

在创建 Web 应用程序之前，我们需要创建一个资源组：

```
az group create \
        --name wsltips-chapter-11-03 \
        --location westeurope
```

在这里，我们使用`az group create`命令创建一个资源组来包含我们将创建的资源。请注意，我们使用了行继续字符（`\`）将命令分割成多行以便阅读。要运行 Web 应用程序，我们需要一个 Azure 应用服务计划来托管它，所以我们将首先创建它：

```
az appservice plan create \
        --resource-group wsltips-chapter-11-03 \
        --name wsltips-chapter-11-03 \
        --sku FREE
```

在这个片段中，我们使用`az appservice plan create`命令在我们刚刚创建的资源组中创建了一个免费的托管计划。现在，我们可以使用该托管计划创建 Web 应用程序：

```
WEB_APP_NAME=wsltips$RANDOM
az webapp create \
        --resource-group wsltips-chapter-11-03 \
        --plan wsltips-chapter-11-03 \
        --name $WEB_APP_NAME
```

在这里，我们为网站生成一个随机名称（因为它需要是唯一的），并将其存储在`WEB_APP_NAME`变量中。然后我们使用`az webapp create`命令。一旦这个命令完成，我们就创建了一个新的网站，并准备好开始使用`az` CLI 进行查询。

## 查询单个值

我们要查询 Web 应用程序的第一件事是它的 URL。我们可以使用`az webapp show`命令列出我们的 Web 应用程序的各种属性：

```
$ az webapp show \
             --name $WEB_APP_NAME \
             --resource-group wsltips-chapter-11-03 \
             --output json
{
  "appServicePlanId": "/subscriptions/67ce421f-bd68-463d-85ff-e89394ca5ce6/resourceGroups/wsltips-chapter-11-02/providers/Microsoft.Web/serverfarms/wsltips-chapter-11-03",
  "defaultHostName": "wsltips28126.azurewebsites.net",
  "enabled": true,
  "enabledHostNames": [
    "wsltips28126.azurewebsites.net",
    "wsltips28126.scm.azurewebsites.net"
  ],
  "id": "/subscriptions/67ce421f-bd68-463d-85ff-e89394ca5ce6/resourceGroups/wsltips-chapter-11-02/providers/Microsoft.Web/sites/wsltips28126",
   ...
  }
}
```

在这里，我们传递了`--output json`开关，以确保无论配置了什么默认格式，我们都能获得 JSON 输出。在这个简化的输出中，我们可以看到有一个`defaultHostName`属性，我们可以用它来构建我们网站的 URL。

提取`defaultHostName`属性的一种方法是使用`jq`，就像我们在*使用 jq*部分中看到的那样：

```
$ WEB_APP_URL=$(az webapp show \
             --name $WEB_APP_NAME \
             --resource-group wsltips-chapter-11-03 \
             --output json  \
             | jq ".defaultHostName" -r)
```

在这个片段中，我们使用`jq`选择`defaultHostName`属性，并传递`-r`开关以获得原始输出，避免它被引用，然后将其分配给`WEB_APP_URL`属性，以便我们可以在其他脚本中使用它。

`az` CLI 还包括使用`az`运行 JMESPath 查询并输出结果的内置查询功能：

```
$ WEB_APP_URL=$(az webapp show \
                --name $WEB_APP_NAME \
                --resource-group wsltips-chapter-11-03 \
                --query "defaultHostName" \
                --output tsv)
```

在这里，我们使用了`--query`选项来传递`"defaultHostName"` JMESPath 查询，它选择了`defaultHostName`属性。我们还添加了`--output tsv`来使用制表符分隔的输出，这样可以防止值被引号包裹。这检索了与之前使用`jq`相同的值，但是使用了`az`完成了所有操作。这在与他人共享脚本时很有用，因为它消除了对依赖的需求。

提示

您可以在[`jmespath.org`](https://jmespath.org)找到有关 JMESPath 的更多详细信息和交互式查询工具。有一个`jp` CLI 用于运行 JMESPath 查询，可以从[`github.com/jmespath/jp`](https://github.com/jmespath/jp)安装。此外，还有一个`jpterm` CLI，它在您的终端中提供了一个交互式 JMESPath，可以从[`github.com/jmespath/jmespath.terminal`](https://github.com/jmespath/jmespath.terminal)安装。

这些工具可以为构建查询时探索 JMESPath 提供一个不错的方式。以`jpterm`为例：

**az webapp show --name $WEB_APP_NAME --resource-group wsltips-chapter-11-03 --output json | jpterm**

在这里，您可以看到将 JSON 输出传输到`jpterm`，然后可以在终端中交互式地进行查询实验。

我们已经看到了通过`az`检索主机名并将其存储在`WEB_APP_URL`变量中的几种方法。现在，要么运行`echo $WEB_APP_URL`来输出值并复制到您的浏览器中，要么运行`wslview https://$WEB_APP_URL`从 WSL 启动浏览器（有关`wslview`的更多详细信息，请参见*第五章*中的*使用 wslview 启动默认 Windows 应用程序*部分，*Linux 到 Windows 互操作性*）：

![图 11.6 - 显示 Azure Web 应用程序占位符站点的屏幕截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/Figure_11.6_B16412.jpg)

图 11.6 - 显示 Azure Web 应用程序占位符站点的屏幕截图

在这个屏幕截图中，您可以看到通过`az` CLI 查询的 URL 加载的占位符站点。接下来，让我们看一下在向 Web 应用程序添加一些内容时，我们将看到更复杂的查询需求。

## 查询和过滤多个值

现在我们已经创建了一个 Web 应用程序，让我们上传一个简单的 HTML 页面。使用 Azure Web 应用程序管理内容有许多选项（请参阅[`docs.microsoft.com/en-us/azure/app-service/`](https://docs.microsoft.com/en-us/azure/app-service/)），但为简单起见，在本节中，我们将使用`curl`通过 FTP 上传单个 HTML 页面。为此，我们需要获取 FTP URL 以及用户名和密码。可以使用`az webapp deployment list-publishing-profiles`命令检索这些值：

```
$ az webapp deployment list-publishing-profiles \
                --name $WEB_APP_NAME \
                --resource-group wsltips-chapter-11-03 \
                -o json
[
  {
    ...
    "publishMethod": "MSDeploy",
    "publishUrl": "wsltips28126.scm.azurewebsites.net:443",
    "userName": "$wsltips28126",
    "userPWD": "evps3kT1Ca7a2Rtlqf1h57RHeHMo9TGQaAjE3hJDv426HKhnlrzoDvGfeirT",
    "webSystem": "WebSites"
  },
  {
    ...
    "publishMethod": "FTP",
    "publishUrl": "ftp://waws-prod-am2-319.ftp.azurewebsites.windows.net/site/wwwroot",
    "userName": "wsltips28126\\$wsltips28126",
    "userPWD": "evps3kT1Ca7a2Rtlqf1h57RHeHMo9TGQaAjE3hJDv426HKhnlrzoDvGfeirT",
    "webSystem": "WebSites"
  }
]
```

这个截断的输出显示了输出中的 JSON 数组。我们需要的值在第二个数组项目中（具有`publishMethod`属性设置为`FTP`的项目）。让我们看看如何使用我们在上一节中看到的`--query`方法来实现这一点：

```
PUBLISH_URL=$(az webapp deployment list-publishing-profiles \
  --name $WEB_APP_NAME \
  --resource-group wsltips-chapter-11-03 \
  --query "[?publishMethod == 'FTP']|[0].publishUrl" \
  --output tsv)
PUBLISH_USER=...
```

在这里，我们使用了一个 JMESPath 查询`[?publishMethod == 'FTP']|[0].publishUrl`。我们可以将查询分解为几个部分：

+   `[?publishMethod == 'FTP']`是过滤数组的语法，在这里我们将其过滤为仅返回包含值为`FTP`的`publishMethod`属性的项目。

+   前面查询的输出仍然是一个项目数组，所以我们使用`|[0]`将数组传输到数组选择器中，以获取第一个数组项目。

+   最后，我们使用`.publishUrl`来选择`publishUrl`属性。

同样，我们使用了`--output tsv`开关来避免结果被引号包裹。这个查询检索了发布 URL，我们可以重复查询，更改属性选择器以检索用户名和密码。

这种方法的一个缺点是我们向`az`发出了三个查询，每个查询都返回我们需要的信息，但是丢弃了除一个值之外的所有值。在许多情况下，这是可以接受的，但有时我们需要的信息是从调用创建资源返回给我们的，在这种情况下，重复调用不是一个选项。在这些情况下，我们可以使用我们之前看到的`jq`方法的轻微变体：

```
CREDS_TEMP=$(az webapp deployment list-publishing-profiles \
                --name $WEB_APP_NAME \
                --resource-group wsltips-chapter-11-03 \
                --output json)
PUBLISH_URL=$(echo $CREDS_TEMP | jq 'map(select(.publishMethod =="FTP"))[0].publishUrl' -r)
PUBLISH_USER=$(echo $CREDS_TEMP | jq 'map(select(.publishMethod =="FTP"))[0].userName' -r)
PUBLISH_PASSWORD=$(echo $CREDS_TEMP | jq 'map(select(.publishMethod =="FTP"))[0].userPWD' -r)
```

在这里，我们存储了来自`az`的 JSON 响应，而不是直接将其传输到`jq`。然后我们可以多次将 JSON 传输到`jq`中以选择我们想要检索的不同属性。通过这种方式，我们可以对`az`进行单次调用，仍然捕获多个值。`jq`查询`map(select(.publishMethod =="FTP"))[0].publishUrl`可以以与我们刚刚看到的 JMESPath 查询类似的方式进行分解。查询的第一部分(`map(select(.publishMethod =="FTP"))`)是选择数组中`publishMethod`属性值为 FTP 的项目的`jq`方式。查询的其余部分选择第一个数组项目，然后捕获`publishUrl`属性以进行输出。

这里还有一个选项，我们将在这里看一下，这是`--query`方法的一个变体，允许我们发出单个查询而不需要`jq`：

```
CREDS_TEMP=($(az webapp deployment list-publishing-profiles \
  --name $WEB_APP_NAME \
  --resource-group wsltips-chapter-11-03 \
  --query "[?publishMethod == 'FTP']|[0].[publishUrl,userName,userPWD]" \
                --output tsv))
PUBLISH_URL=${CREDS_TEMP[0]}
PUBLISH_USER=${CREDS_TEMP[1]}
PUBLISH_PASSWORD=${CREDS_TEMP[2]}
```

这段代码建立在之前的`--query`方法之上，但有一些不同之处需要注意。

首先，我们使用`.[publishUrl,userName,userPWD]`而不是简单的`.publishUrl`作为 JMESPath 查询中的最终选择器。这样做的结果是生成一个包含`publishUrl`、`userName`和`userPWD`属性值的数组。

这些属性数组以制表符分隔的值输出，并且通过将`az`命令的执行结果括在括号中来将结果视为 bash 数组：`CREDS_TEMP=($(az...))`。

这两个步骤允许我们使用`--query`从单个`az`调用中返回多个值，并将结果存储在数组中。输出中的最后几行显示将数组项分配给命名变量以便于使用。

无论使用哪种选项来设置发布环境变量，我们现在可以从示例内容的`chapter-11/03-working-with-az`文件夹中的终端上传`index.html`文件：

```
curl -T index.html -u $PUBLISH_USER:$PUBLISH_PASSWORD $PUBLISH_URL/
```

在这里，我们使用`curl`使用我们查询的 URL、用户名和密码将`index.html`文件上传到 FTP。现在我们可以回到浏览器并重新加载页面。我们将得到以下结果：

![图 11.7 - 屏幕截图显示带有我们上传内容的 Web 应用程序](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/wsl2-tip-trk-tech/img/B16412_11.7.jpg)

图 11.7 - 屏幕截图显示带有我们上传内容的 Web 应用程序

这个屏幕截图显示了我们之前创建的 Web 应用程序现在返回了我们刚刚上传的简单 HTML 页面。

现在我们已经完成了我们创建的 Web 应用程序（和应用服务计划），我们可以删除它们：

```
az group delete --name wsltips-chapter-11-03
```

这个命令将删除我们一直在使用的`wsltips-chapter-11-03`资源组以及其中创建的所有资源。

本节中的示例显示了使用`curl`将单个页面 FTP 到我们创建的 Azure Web 应用程序，这为使用`az`进行查询提供了一个方便的示例，但 Azure Web 应用程序提供了多种部署内容的选项-有关更多详细信息，请参阅以下文章：[`docs.microsoft.com/archive/msdn-magazine/2018/october/azure-deploying-to-azure-app-service-and-azure-functions`](https://docs.microsoft.com/archive/msdn-magazine/2018/october/azure-deploying-to-azure-app-service-and-azure-functions)。值得注意的是，对于托管静态网站，Azure 存储静态网站托管可能是一个很好的选择。有关操作步骤，请参阅[`docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-static-website-how-to?tabs=azure-cli`](https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-static-website-how-to?tabs=azure-cli)。

在本节中，您已经看到了使用`az` CLI 进行查询的多种方法。您已经了解了如何将默认输出设置为表格格式，以便进行可读的交互式查询。在脚本编写时，您已经了解了如何使用 JSON 输出并使用`jq`进行处理。您已经学会了如何使用`--query`开关进行 JMESPath 查询，以便使用`az`命令直接过滤和选择响应中的值。在本节中，我们只看了`az` CLI（用于 Web 应用程序）的一个狭窄片段-如果您有兴趣探索更多`az`的广度，请参阅[`docs.microsoft.com/cli/azure`](https://docs.microsoft.com/cli/azure)。

在下一节中，我们将看看另一个 CLI-这次是用于 Kubernetes 的 CLI。

# 使用 Kubernetes CLI（kubectl）

在构建容器化应用程序时，Kubernetes 是容器编排器的常见选择。有关 Kubernetes 的介绍，请参阅*第七章*，*在 WSL 中设置 Kubernetes*部分。Kubernetes 包括一个名为`kubectl`的 CLI，用于从命令行处理 Kubernetes。在本节中，我们将在 Kubernetes 中部署一个基本网站，然后查看使用`kubectl`查询有关它的信息的不同方法。

在*第七章*，*在 WSL 中使用容器*部分，我们看到了如何使用 Docker Desktop 在本地机器上设置 Kubernetes。在这里，我们将探索使用云提供商设置 Kubernetes 集群。以下说明适用于 Azure，但如果您熟悉另一个具有 Kubernetes 服务的云，则可以使用该云。如果您想跟着操作，但尚未拥有 Azure 订阅，可以在 https://azure.microsoft.com/free/上注册免费试用。

让我们开始安装`kubectl`。

## 安装和配置 kubectl

有多种选项可用于安装`kubectl`（可以在[`kubernetes.io/docs/tasks/tools/install-kubectl/#install-kubectl-binary-with-curl-on-linux`](https://kubernetes.io/docs/tasks/tools/install-kubectl/#install-kubectl-binary-with-curl-on-linux)找到），但最简单的方法是从您的 WSL 分发版运行以下命令：

```
curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
chmod +x ./kubectl
sudo mv ./kubectl /usr/local/bin/kubectl
```

这些命令下载最新的`kubectl`二进制文件，将其标记为可执行文件，然后将其移动到您的`bin`文件夹中。完成后，您应该能够运行`kubectl version --client`来检查`kubectl`是否正确安装：

```
$ kubectl version --client
Client Version: version.Info{Major:"1", Minor:"19", GitVersion:"v1.19.2", GitCommit:"f5743093fd1c663cb0cbc89748f730662345d44d", GitTreeState:"clean", BuildDate:"2020-09-16T13:41:02Z", GoVersion:"go1.15", Compiler:"gc", Platform:"linux/amd64"}
```

在这里，我们已经看到了来自`kubectl`的输出，显示我们已安装版本`v1.19.2`。

`kubectl`实用程序有各种命令，并且启用 bash 自动补全可以使您更加高效。要做到这一点，请运行以下命令：

```
echo 'source <(kubectl completion bash)' >>~/.bashrc
```

这将在您的`.bashrc`文件中添加一个命令，以便在 bash 启动时自动加载`kubectl` bash 自动补全。要尝试它，请重新启动 bash 或运行`source ~/.bashrc`。现在，您可以输入`kubectl ver<TAB> --cli<TAB>`来获取以前的`kubectl version --client`命令。

提示

如果您觉得`kubectl`输入太多，可以通过运行以下命令创建一个别名：

**echo 'alias k=kubectl' >>~/.bashrc**

**echo 'complete -F __start_kubectl k' >>~/.bashrc**

这些命令将添加到`.bashrc`中，以将`k`配置为`kubectl`的别名，并为`k`设置 bash 自动补全。

有了这个，您可以使用命令，比如`k version – client`，并且仍然可以获得 bash 自动补全。

现在我们已经安装和配置了`kubectl`，让我们创建一个 Kubernetes 集群来使用它。

## 创建一个 Kubernetes 集群

以下说明将带您完成使用`az`创建 Kubernetes 集群的过程。如果您还没有安装`az`，请参考本章前面的*安装和配置 Azure CLI*部分。

第一步是创建一个资源组来包含我们的集群：

```
az group create \
        --name wsltips-chapter-11-04 \
        --location westeurope
```

在这里，我们正在创建一个名为`wsltips-chapter-11-04`的资源组，位于`westeurope`区域。

接下来，我们创建 AKS 集群：

```
az aks create \
        --resource-group wsltips-chapter-11-04 \
        --name wsltips \
        --node-count 2 \
        --generate-ssh-keys
```

此命令在我们刚创建的资源组中创建了一个名为`wsltips`的集群。此命令将需要几分钟来运行，当它完成后，我们将拥有一个运行有两个工作节点的 Kubernetes 集群，我们可以在其中运行我们的容器工作负载。

最后一步是设置`kubectl`，以便它可以连接到集群：

```
az aks get-credentials \
       --resource-group wsltips-chapter-11-04 \
       --name wsltips
```

在这里，我们使用`az aks get-credentials`来获取我们创建的集群的凭据，并将它们保存在`kubectl`的配置文件中。

现在，我们可以运行诸如`kubectl get services`之类的命令来列出已定义的服务：

```
$ kubectl get services
NAME            TYPE           CLUSTER-IP     EXTERNAL-IP     PORT(S)        AGE
kubernetes      ClusterIP      10.0.0.1       <none>          443/TCP        7m
```

此输出显示了我们在创建的集群中 Kubernetes 服务的列表，证明我们已成功连接到了集群。

现在我们有了一个 Kubernetes 集群，并且`kubectl`已配置好连接到它，让我们将一个测试网站部署到它上面。

## 部署基本网站

为了帮助探索`kubectl`，我们将部署一个基本网站。然后我们可以使用它来查看使用`kubectl`查询信息的不同方式。

该书的附带代码包含了一个用于此部分的文件夹，其中包含了 Kubernetes YAML 文件。您可以从[`github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques`](https://github.com/PacktPublishing/Windows-Subsystem-for-Linux-2-WSL-2-Tips-Tricks-and-Techniques)获取此代码。此部分的内容位于`chapter-11/04-working-with-kubectl`文件夹中。`manifests`文件夹包含了一些定义要部署的 Kubernetes 资源的 YAML 文件：

+   包含一个简单 HTML 页面的**ConfigMap**

+   一个`nginx`镜像，并配置它从 ConfigMap 加载 HTML 页面

+   一个`nginx`部署

要部署网站，请启动您的 WSL 发行版并导航到`chapter-11/04-working-with-kubectl`文件夹。然后运行以下命令：

```
$ kubectl apply -f manifests
configmap/nginx-html created
deployment.apps/chapter-11-04 created
service/chapter-11-04 created
```

在这里，我们使用`kubectl apply -f manifests`来创建`manifests`文件夹中的 YAML 文件描述的资源。命令的输出显示已创建的三个资源。

现在，我们可以运行`kubectl get services chapter-11-04`来查看已创建服务的状态：

```
$ kubectl get services chapter-11-04
NAME            TYPE           CLUSTER-IP    EXTERNAL-IP   PORT(S)        AGE
chapter-11-04   LoadBalancer   10.0.21.171   <pending>     80:32181/TCP   3s
```

在这里，我们看到`chapter-11-04`服务的类型是`LoadBalancer`。在 AKS 中，`LoadBalancer`服务将自动使用*Azure 负载均衡器*暴露，并且这可能需要一些时间来进行配置 - 请注意输出中`EXTERNAL_IP`的`<pending>`值，显示负载均衡器正在进行配置的过程。在下一节中，我们将看看如何查询此 IP 地址。

## 使用 JSONPath 查询

正如我们刚才看到的，创建服务后立即获得服务的外部 IP 地址是不可用的，因为 Azure 负载均衡器需要进行配置和配置。我们可以通过以 JSON 格式获取服务输出来看到底层数据结构是什么样子的：

```
$ kubectl get services chapter-11-04 -o json
{
    "apiVersion": "v1",
    "kind": "Service",
    "metadata": {
        "name": "chapter-11-04",
        "namespace": "default",
       ...
    },
    "spec": {
        ...
        "type": "LoadBalancer"
    },
    "status": {
        "loadBalancer": {}
    }
}
```

在这里，我们看到了应用`-o json`选项的截断 JSON 输出。请注意`status`下`loadBalancer`属性的空值。如果我们等待一会儿然后重新运行命令，我们会看到以下输出：

```
    "status": {
        "loadBalancer": {
            "ingress": [
                {
                    "ip": "20.50.162.63"
                }
            ]
        }
    }
```

在这里，我们可以看到`loadBalancer`属性现在包含一个带有 IP 地址数组的`ingress`属性。

我们可以使用`kubectl`的内置`jsonpath`功能直接查询 IP 地址：

```
$ kubectl get service chapter-11-04 \
      -o jsonpath="{.status.loadBalancer.ingress[0].ip}"
20.50.162.63
```

在这里，我们使用了`-o jsonpath`来提供一个 JSONPath 查询：`{.status.loadBalancer.ingress[0].ip}`。此查询直接映射到我们要查询的 JSON 结果的路径。有关 JSONPath 的更多详细信息（包括在线交互式评估器），请参见[`jsonpath.com/`](https://jsonpath.com/)。这种技术在脚本中很方便使用，附带的代码中有一个`scripts/wait-for-load-balancer.sh`脚本，它等待负载均衡器进行配置，然后输出 IP 地址。

直接在`kubectl`中使用 JSONPath 很方便，但与`jq`相比，JSONPath 可能有一定的局限性，有时我们需要进行切换。接下来我们将看一个这样的场景。

## 扩展网站

我们刚刚创建的部署只运行一个`nginx` Pod 的实例。我们可以通过运行以下命令来查看：

```
$ kubectl get pods -l app=chapter-11-04
NAME                           READY   STATUS    RESTARTS   AGE
chapter-11-04-f4965d6c4-z425l   1/1     Running   0         10m
```

在这里，我们列出了与`deployment.yaml`中指定的`app=chapter-11-04`标签选择器匹配的 Pods。

Kubernetes 部署资源提供的一个功能是轻松地扩展部署的 Pod 数量：

```
$ kubectl scale deployment chapter-11-04 --replicas=3
deployment.apps/chapter-11-04 scaled
```

在这里，我们指定要扩展的部署和我们想要将其扩展到的实例数（`replicas`）。如果我们再次查询 Pods，现在将看到三个实例：

```
$ kubectl get pods -l app=chapter-11-04
NAME                           READY   STATUS    RESTARTS   AGE
chapter-11-04-f4965d6c4-dptkt   0/1     Pending   0        12s
chapter-11-04-f4965d6c4-vxmks   1/1     Running   0        12s
chapter-11-04-f4965d6c4-z425l   1/1     Running   0         11
```

此输出列出了部署的三个 Pod，但请注意其中一个处于`Pending`状态。原因是部署定义要求每个 Pod 使用完整的 CPU，但集群只有两个工作节点。虽然每个节点运行的机器都有两个 CPU，但其中一些是为工作节点进程本身保留的。尽管这种情况是故意构造出来的，以说明使用`kubectl`进行查询，但遇到类似问题是很常见的。

找到一个未运行的 Pod 后，我们可以进一步调查它：

```
$ kubectl get pod chapter-11-04-f4965d6c4-dptkt -o json
{
    "metadata": {
        ...
        "name": "chapter-11-04-f4965d6c4-dptkt",
        "namespace": "default",
    },
    ...
    "status": {
        "conditions": [
            {
                "lastTransitionTime": "2020-09-27T19:01:07Z",
                "message": "0/2 nodes are available: 2 Insufficient cpu.",
                "reason": "Unschedulable",
                "status": "False",
                "type": "PodScheduled"
            }
        ],
    }
}
```

在这里，我们请求了未运行的 Pod 的 JSON，并且截断的输出显示了一个`conditions`属性。这里有一个条目表明 Pod 无法被调度（也就是说，Kubernetes 找不到集群中的任何位置来运行它）。在下一节中，我们将编写一个查询，从 Pod 列表中查找任何无法被调度的 Pod。

## 使用 jq 进行查询

让我们看看如何编写一个查询，查找具有`type`为`PodScheduled`且`status`设置为`False`的条件的任何 Pod。首先，我们可以使用以下命令获取 Pod 的名称：

```
$ kubectl get pods -o json | \
    jq '.items[] | {name: .metadata.name}'
{
  "name": "chapter-11-04-f4965d6c4-dptkt"
}
{
  "name": "chapter-11-04-f4965d6c4-vxmks"
}
...
```

在这里，我们将`kubectl`的 JSON 输出传递给`jq`，并使用选择器提取输入`items`数组中每个项目的`metadata.name`作为输出中的`name`属性。这使用了我们在本章前面看到的相同技术-有关更多详细信息，请参阅*使用 jq*部分。

接下来，我们想要包括`status`属性中的条件：

```
$ kubectl get pods -o json | \
    jq '.items[] | {name: .metadata.name, conditions: .status.conditions} '
{
  "name": "chapter-11-04-f4965d6c4-dptkt",
  "conditions": [
    {
      "lastProbeTime": null,
      "lastTransitionTime": "2020-09-27T19:01:07Z",
      "message": "0/2 nodes are available: 2 Insufficient cpu.",
      "reason": "Unschedulable",
      "status": "False",
      "type": "PodScheduled"
    }
  ]
}{
  ...
}
```

在这里，我们包含了所有的条件，但由于我们只想要那些尚未被调度的条件，我们只想包括特定的条件。为此，我们可以使用`jq`的`select`过滤器，它处理一个值数组，并通过那些匹配指定条件的值。在这里，我们将使用它来过滤状态条件，只包括那些`type`设置为`PodScheduled`且`status`设置为`False`的条件：

```
$ kubectl get pods -o json | \
    jq '.items[] | {name: .metadata.name, conditions: .status.conditions[] | select(.type == "PodScheduled" and .status == "False")}'
{
  "name": "chapter-11-04-f4965d6c4-dptkt",
  "conditions": {
    "lastProbeTime": null,
    "lastTransitionTime": "2020-09-27T19:01:07Z",
    "message": "0/2 nodes are available: 2 Insufficient cpu.",
    "reason": "Unschedulable",
    "status": "False",
    "type": "PodScheduled"
  }
}
```

在这里，我们将`select(.type == "PodScheduled" and .status == "False")`应用于被分配给`conditions`属性的条件集。查询的结果只是具有失败状态条件的单个项目。

我们可以对查询进行一些最后的微调：

```
$ kubectl get pods -o json | \
  jq '[.items[] | {name: .metadata.name, conditions: .status.conditions[] | select(.type == "PodScheduled" and .status == "False")} | {name, reason: .conditions.reason, message: .conditions.message}]'
[
  {
    "name": "chapter-11-04-f4965d6c4-dptkt",
    "reason": "Unschedulable",
    "message": "0/2 nodes are available: 2 Insufficient cpu."
  }
]
```

在这里，我们对选择器进行了一些最后的更新。第一个是将先前选择器的结果传递到`{name, reason: .conditions.reason, message: .conditions.message}`，以仅提取我们感兴趣的字段，使输出更易于阅读。第二个是将整个选择器包装在方括号中，以便输出是一个 JSON 数组。这样，如果有多个无法调度的 Pod，我们将获得有效的输出，如果需要，可以进一步处理。

如果您经常使用这个命令，您可能希望将其保存为一个 bash 脚本，甚至将其添加到您的`.bashrc`文件中作为别名：

```
alias k-unschedulable="kubectl get pods - json | jq '[.items[] | {name: .metadata.name, conditions: .status.conditions[] | select(.type == \"PodScheduled\" and .status == \"False\")} | {name, reason: .conditions.reason, message: .conditions.message}]'"
```

在这里，我们为列出无法调度的 Pod 的命令创建了一个`k-unschedulable`别名。请注意，引号（`"`）已经用反斜杠（`\"`）进行了转义。

这种技术可以应用于 Kubernetes 中的各种资源。例如，Kubernetes 中的节点具有状态条件，指示节点是否正在耗尽内存或磁盘空间，可以修改此查询以便轻松识别这些节点。

总的来说，我们遵循了一个通用的模式，首先是获取您感兴趣的资源的 JSON 输出。从那里开始，如果您想要检索的值是一个简单的值，那么 JSONPath 方法是一个值得考虑的好方法。对于更复杂的过滤或输出格式化，`jq`是您工具包中一个方便的工具。Kubernetes 为其资源提供了丰富的信息，熟练使用`kubectl`及其 JSON 输出可以为您提供强大的查询能力。

现在我们已经完成了集群，我们可以删除包含的资源组：

```
az group delete --name wsltips-chapter-11-04
```

这个命令将删除我们一直在使用的`wsltips-chapter-11-04`资源组以及其中创建的所有资源。

在本节中，您已经涵盖了从设置`kubectl`的 bash 完成到在 Kubernetes 集群中使用`kubectl`查询资源信息的方法。无论您是为特定资源查询单个值还是在资源集上过滤数据，使用这里的技术都为脚本化工作流程的步骤打开了巨大的机会。

# 总结

在本章中，您看到了如何改进在 WSL 中使用 Git 的方式。您看到了如何配置 Windows 的 Git 凭据管理器，以便在 WSL 中重用保存的 Git 凭据，并在需要新的 Git 凭据时在 Windows 中提示您。之后，您看到了一系列查看 Git 历史记录的选项，讨论了它们的优缺点，以便您选择适合您的正确方法。

在本章的其余部分，您了解了如何在 WSL 中处理 JSON 数据，首先是深入了解`jq`和 PowerShell 的 JSON 功能。有了这个背景，您还看到了一些使用`az`和`kubectl`进行部署的 JSON 工作示例。除了涵盖每个 CLI 可能面临的场景外，示例还演示了可以应用于提供 JSON 数据的其他 CLI（或 API）的技术。能够有效地处理 JSON 数据为您提供了强大的能力，可以在脚本中使用，节省您的时间。

这是本书的最后一章，我希望我已经成功地传达了我对 WSL 2 以及它带来的可能性的一些兴奋。在 Windows 上享受 Linux 吧！
