# Python 软件工程实用指南（二）

> 原文：[`zh.annas-archive.org/md5/7ADF76B4555941A3D7672888F1713C3A`](https://zh.annas-archive.org/md5/7ADF76B4555941A3D7672888F1713C3A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：设置项目和流程

我们的第一个迭代是为所有以下迭代以及项目最初完成后的任何开发工作做好准备。这种准备工作需要为预期复杂程度的任何新开发工作进行，但可能不会被分解为自己的迭代。许多基础结构的创建可以作为其他迭代的一部分来管理；例如，当需要它的第一个开发开始时创建项目的结构。采取这种方法的权衡是，较早的定义工作很可能会在后续开发展开时被显著改变，因为最初的结构无法容纳多个 Python 虚拟环境，或者将新项目添加到系统代码库中。

拥有一些标准的结构定义，比如[第六章](https://cdp.packtpub.com/hands_on_software_engineering_with_python/wp-admin/post.php?post=30&action=edit)，《开发工具和最佳实践》，将最大程度地减少这些问题，但可能无法完全防止它们。

本章将涵盖大多数项目共有的设置和准备工作：

+   源代码管理（SCM）

+   项目组织

+   单元测试结构

+   构建和部署流程

# 迭代目标

这次迭代的交付成果主要集中在以下方面：

+   主存储库，存储在 Git 服务器或服务（例如本地服务器、GitHub 或 Bitbucket）中，包含系统及其组件项目的完整空项目结构

+   系统中每个可部署的类库或应用程序的组件项目

+   系统中每个组件项目的单元测试套件都可以执行，并且其执行对每个组件项目都通过

+   每个组件项目的构建过程-也是可执行的-会产生一个可部署的软件包，即使该软件包起初是基本无用的

# 故事和任务的组装

开发人员的需求也可以表达为故事，并附有要执行的任务。这些基础故事可能会在多个项目中重复使用，并且如果是这样，它们可能会随着时间的推移而不断发展，以更好地捕捉跨开发工作的常见需求和目标-即使是对于根本不同的系统。这些应该足以作为现在的起点：

+   作为开发人员，我需要知道系统的源代码将如何被管理和版本控制，以便我能够适当地保留/存储我编写的代码：

1.  为系统创建一个空的 SCM 存储库-`hms_sys`

1.  填充存储库所需的基线信息和文档，以供持续使用

1.  建立和分发开发团队成员访问存储库所需的凭据

+   作为开发人员，我需要知道系统的完整结构看起来是什么样子，至少在高层次上，以便我能够编写符合该结构的代码。这将涉及：

1.  分析用例以及逻辑和物理架构，以定义组件项目的需求和结构

1.  为每个组件项目构建标准的项目起点

1.  为每个组件项目实施一个最小的`setup.py`，完成源代码包的构建

1.  确定是否要为组件项目使用 Python 虚拟环境，实施它们，并记录如何复制它们

+   作为开发人员，我需要知道如何以及在哪里为代码库编写单元测试，以便在编写代码后创建单元测试。我还需要确保代码经过彻底测试：

1.  定义单元测试的标准/要求（覆盖率、按类型的标准值等）

1.  实施强制执行这些标准的机制

1.  定义单元测试代码将存放在组件项目结构中的位置

1.  为每个组件项目实施一个基本的顶层测试，以确保没有任何失败

+   作为开发人员，我需要知道如何将组件项目的单元测试集成到该组件项目的构建过程中，以便构建可以自动执行单元测试，其中包括：

+   确定如何将单元测试集成到构建过程中；以及

+   确定如何处理不同环境的构建/测试集成

# 设置 SCM

由于此迭代中需要进行的大部分活动最终需要存储在 SCM 中，因此将首先进行列表中的第一个故事及其任务：

+   作为开发人员，我需要知道系统的源代码将如何被管理和版本控制，以便我能够适当地保留/存储我编写的代码：

1.  为系统创建一个空的 SCM 存储库——`hms_sys`

1.  填充存储库所需的基线信息和文档，以供日常使用

1.  建立并分发团队成员访问存储库所需的凭据

`hms_sys`的代码将存储在 Bitbucket（[`bitbucket.org`](https://bitbucket.org)）中的 Git 存储库中，因此第一步是在那里设置一个新存储库：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/3633e5d7-d6fd-47de-97a4-ea8ac5c36ee2.png)

新存储库的设置如下：

+   所有者：拥有存储库的用户。如果多个用户通过 Bitbucket 帐户访问存储库，或者与之关联的组，这些用户和组将作为此设置的选项可用。

+   存储库名称：存储库的（必需）名称。理想情况下，存储库名称应该与其包含的系统或项目轻松关联起来，由于`hms_sys`既是整个项目的名称，而且尚未被使用，因此被使用。

+   访问级别：确定存储库是公共的还是私有的。由于`hms_sys`不打算供公众查阅或分发，因此存储库已被设置为私有。

+   包括 README？：系统是否将在创建过程中创建一个`README`文件。选项如下：

+   否：如果需要/希望，将需要手动创建文件。

+   是，带模板：创建一个带有最少信息的基本文件。选择此选项是为了创建一个基本的`README`文件。

+   是，有教程（适用于初学者）。

+   版本控制系统：允许存储库使用 Git 或 Mercurial 作为其 SCM 引擎。选择了 Git，因为这是我们决定使用的。

高级设置必须扩展才能使用，并且如下所示：

+   描述：如果选择了“是，带模板”选项，此处提供的任何描述都将添加到`README`文件中。

+   派生：控制是否/如何允许从存储库派生。选项如下：

+   允许派生：任何有权限的人都可以派生存储库

+   仅允许私有派生

+   不允许派生

+   项目管理：允许将问题跟踪和 wiki 系统与存储库集成。

+   语言：指定存储库中代码的主要编程语言。最初，此设置除了按其主要语言对存储库进行分类外，并不起作用。一些 SCM 提供商将使用语言设置来预先填充 Git 的`.gitignore`文件，其中包含常被忽略的文件模式，因此如果可能的话，指定它是有利的。

单击“创建存储库”按钮后，将创建存储库：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/bd3bedd7-14cd-4d16-9248-6e73670d0d99.png)

从任何存储库的概述页面，连接和克隆/拉取存储库的 HTTPS 和 SSH 选项都可用，有必要权限的任何人都可以克隆它（以任何首选方式）到本地副本进行操作：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/c9c540d9-904a-4c59-98e7-a05af6cc69c8.png)有几种初始化新的 Git 存储库的方法。这个过程从存储库的提供者开始，确保存储库格式良好且可访问，同时允许进行一些初始配置和文档设置，以后不必手动完成。

此时，故事中的两项任务已解决：

1.  为系统创建一个空的 SCM 存储库——`hms_sys`。

1.  建立并分发开发团队成员访问存储库所需的凭据。由于存储库是通过外部服务提供商的界面创建的，因此访问所需的凭据是在那里管理的，任何与存储库的帐户或组相关联的用户帐户都具有他们需要的访问权限，或者可以通过提供商系统中的用户管理来获得访问权限。

剩下的任务，填充了基线信息和持续使用所需的文档，与尚未解决的项目结构有关，但仍然有一些可以解决的独立项目。

首先是在顶层存储库目录中创建和记录基本组件项目。最初，创建一个顶层项目，包含整个系统代码库可能是一个好主意——这将提供一个单一的项目，用于组织跨两个或多个组件项目的项目，以及涵盖整个系统的任何内容。

在 Geany 中，通过使用 Project → New 来完成，提供项目名称、项目文件路径和项目的基本路径：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/f2e94a29-c46c-450b-a006-5ed04eae1f5d.png)

由于 Geany 项目文件存储可能因机器而异的文件系统路径，这些路径需要添加到 Git 的`.gitignore`文件中：

```py
# .gitignore for hms_sys project
# Geany project-files
*.geany
```

`.gitignore`文件最终是 Git 提交或推送代码到中央存储库时 Git 将忽略的文件和/或文件夹的列表。与`.gitignore`中路径匹配的任何文件或文件夹将不会被 SCM 跟踪。

此外，可能需要记录创建本地`hms_sys.geany`文件的说明，以便任何其他需要的开发人员可以根据需要创建。这类信息可以放入`README.md`文件中，并且在添加系统的组件项目时将进行类似的工作：

```py
# hms_sys

The system-level repository for the hms_sys project, from "Hands On 
Software Engineering with Python," published by Packt.

## Geany Project Set-up

Geany project-files (`*.geany`) are in the `.gitignore` for the entire 
repository, since they have filesystem-specific paths that would break 
as they were moved from one developer's local environment to another. 
Instructions for (re-)creating those projects are provided for each.

### HMS System (Overall) -- `hms_sys.geany`

This is an over-arching project that encompasses *all* of the component 
projects. It can be re-created by launching Geany, then using 
Project → New and providing:

 * *Name:* HMS System (Overall)
 * *Filename:* `[path-to-git-repo]/hms_sys/hms_sys.geany`
 * *Base path:* `[path-to-git-repo]/hms_sys`
```

一旦这些更改被暂存、本地提交并推送到主存储库，那里应该出现一个修订后的`README.md`文件和一个新的`.gitignore`，但不会出现`hms_sys.geany`项目文件：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/a1d0b88d-71d2-413b-bcf5-a0fe8a54df03.png)

随着组件项目被添加到代码库中，应该遵循相同类型的文档和设置，产生类似的结果。此时，第一个故事的最终任务已经完成，如果被判定为完成并获得批准，那么它将被审查和关闭。

# 创建组件项目的存根

然后，进行下一个故事：

+   作为开发人员，我需要知道系统的完整结构是什么样子，至少在高层次上，这样我才能编写适合该结构的代码：

1.  分析用例和逻辑和物理架构，以定义组件项目的需求和结构。

1.  为每个确定的组件项目构建标准项目起点

1.  为每个组件项目实现一个最小的`setup.py`，完成源包构建

# 组件项目分析

逻辑架构以及[第六章](https://cdp.packtpub.com/hands_on_software_engineering_with_python/wp-admin/post.php?post=30&action=edit)的用例图，*开发工具和最佳实践*，指出了三个明显的组件项目，需要分别为以下内容进行核算：

+   工匠应用程序

+   工匠门户

+   审查/管理应用程序

这些组件项目中的每一个都需要访问一些常见的对象类型——它们都需要能够处理**产品**实例，并且它们中的大多数也需要能够处理**工匠**和**订单**实例：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/4d63b4a0-ca46-4c5d-80a0-24978af874b5.png)

可能还有其他业务对象，从这个分解中并不立即显而易见，但是有任何业务对象的事实都表明可能需要第四个组件项目来收集提供这些业务对象及其功能的代码。考虑到这一点，初始的组件项目结构归结如下：

+   **HMS 核心**（`hms-core`）：一个类库，收集所有基线业务对象定义，以提供**工匠**、**产品**和**订单**等对象的表示

+   **中央办公室应用**（`hms-co-app`）：提供一个可执行的应用程序，允许中央办公室工作人员执行需要与**工匠**关于**产品**、**订单**以及可能其他项目进行通信的各种任务

+   **工匠应用**（`hms-artisan`）：提供一个可执行的本地应用程序，允许**工匠**管理**产品**和**订单**，根据需要与中央办公室进行通信

+   **HMS 工匠网关**（`hms-gateway`）：提供一个可执行服务，**工匠**应用程序和中央办公室应用程序用于在工匠和中央办公室之间发送信息

# 组件项目设置

关于`hms-core`代码将如何包含在需要它的其他项目的分发中，稍后将需要做出一些决定，但这些不需要立即解决，因此它们将被搁置。与此同时，为每个组件项目设置起点项目结构是下一步。目前，基本结构在所有四个组件项目中都是相同的；唯一的区别在于各种文件和目录的名称。

以`hms-core`为例，因为这是第一个逻辑上要开始工作的代码集，项目结构将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/3246869b-f7de-4208-9ee1-e93b0521f081.png)

# 打包和构建过程

为项目设置最小标准的 Python 打包，并提供基本的构建过程，对之前讨论过的`setup.py`和`Makefile`文件几乎没有做出任何改变。在编写代码之前只有一些具体的内容可用：`setup.py`将使用的包名称和主包的顶级目录，以及可以添加到`Makefile`中的`setup.py`文件。`Makefile`的更改是最简单的：

```py
# Makefile for the HMS Core (hms-core) project

main: test setup
        # Doesn't (yet) do anything other than running the test and 
        # setup targets

setup:
        # Calls the main setup.py to build a source-distribution
        # python setup.py sdist

test:
        # Executes the unit-tests for the package, allowing the build-
        # process to die and stop the build if a test fails
```

`setup.py`文件，尽管它已经填充了一些起始数据和信息，但仍然基本上是我们之前看到的同样基本的起点文件：

```py
#!/usr/bin/env python

from setuptools import setup

# The actual setup function call:
setup(
    name='HMS-Core',
    version='0.1.dev0',
    author='Brian D. Allbee',
    description='',
    package_dir={
        '':'src',
        # ...
    },
    # Can also be automatically generated using 
    #     setuptools.find_packages...
    packages=[
        'hms_core',
        # ...
    ],
    package_data={
#        'hms_core':[
#            'filename.ext',
#            # ...
#        ]
    },
    entry_points={
#        'console_scripts':[
#            'executable_name = namespace.path:function',
#            # ...
#        ],
    },
)
```

这个结构暂时还不会包括核心包之外的各种目录和文件——在这一点上，没有迹象表明它们中的任何一个是必需的，因此它们的包含将被推迟，直到确实需要它们。即使没有这些，`setup.py`文件也可以成功构建和安装源分发包，尽管在构建过程中会抛出一些警告，并且安装的包目前还没有提供任何功能：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/41827bb6-0523-4d13-bd79-6c1031958583.png)

在更大（或至少更正式结构化）的开发商店中，组件项目的构建/打包过程可能需要适应不同环境的不同构建：

+   本地环境，比如开发人员的本地机器

+   一个共享的开发环境，所有开发人员的本地代码更改首先混合在一起

+   一个用于 QA 和更广泛的集成测试的共享测试服务器

+   使用真实的、类似生产的数据的用户验收测试服务器，可以用来向需要最终批准变更的人演示功能

+   具有完整生产数据副本访问权限的暂存环境，以便能够执行需要访问该数据集的负载和其他测试

+   live 环境/构建代码库

至少有一些潜力需要在这些不同的构建（`local`、`dev`、`test`、`stage`和`live`，用户验收构建暂时假定与阶段构建相同）之间进行重大区分。然而，在开发工作的这一阶段，实际上并没有什么可以区分的，因此唯一能做的就是计划如果需要时会发生什么。

在任何给定环境需要完全不同的包结构之前，当前的`setup.py`文件将保持不变。几乎不太可能存在一个环境特定的需求，这种需求在所有环境中都不常见。如果确实出现这种需求，那么方法将是为每个具有任何独特需求的环境创建一个单独的`setup.py`，并手动或通过`Makefile`执行该特定的`setup.py`。经过一些谨慎和思考，这应该可以将任何特定于环境的差异包含在一个单一位置，并以合理标准的方式进行。

这意味着`Makefile`将需要进行更改。具体来说，每个特定环境的构建过程（从`dev`到`live`）都需要一个目标，并且需要一种管理特定环境文件的方法。由于`make`过程可以操作文件，创建目录等，将使用以下策略：

+   通过为特定环境的文件添加构建目标/环境名称前缀来识别特定于环境的文件。例如，代码库中将有一个`dev-setup.py`文件，以及一个`test-setup.py`文件，依此类推。

+   修改`Makefile`以复制项目代码树中所有可以更改（和销毁）的相关文件，而不影响核心项目文件

+   添加一个过程，将在临时副本中查找并重命名所有特定于环境的文件，以满足特定环境的构建需求，并删除临时树中与构建无关的特定环境文件。

+   执行`setup.py`文件

对`Makefile`的更改将至少在起点上看起来像这样。

首先，定义一个通用的临时构建目录——本地构建将是默认的，并且将简单地执行标准的`setup.py`文件，就像原始过程一样

```py
# Makefile for the HMS Core (hms-core) project
TMPDIR=/tmp/build/hms_core_build

local: setup
 # Doesn't (yet) do anything other than running the test and 
 # setup targets

setup:
 # Calls the main setup.py to build a source-distribution
 ~/py_envs/hms/core/bin/python setup.py sdist

unit_test:
 # Executes the unit-tests for the package, allowing the build-
 # process to die and stop the build if a test fails
 ~/py_envs/hms/core/bin/python setup.py test
```

创建一个新的目标`build_dir`，用于创建临时构建目录，并将可以成为任何构建的项目文件复制到其中

```py
build_dir:
 # Creates a temporary build-directory, copies the project-files 
 # to it.
 # Creating "$(TMPDIR)"
 mkdir -p $(TMPDIR)
 # Copying project-files to $(TMPDIR)
 cp -R bin $(TMPDIR)
 cp -Ret cetera$(TMPDIR)
 cp -R src $(TMPDIR)
 cp -R var $(TMPDIR)
 cp setup.py $(TMPDIR)
```

为每个环境编写一个准备目标，以及每个环境的最终目标，将重命名和删除文件，并在临时构建目录中执行`setup.py`文件

```py
dev_prep:
 # Renames any dev-specific files so that they will be the "real" 
 # files included in the build.
 # At this point, there are none, so we'll just exit

dev: unit_test build_dir dev_prep
 # A make-target that generates a build intended to be deployed 
 # to a shared development environment.
 cd $(TMPDIR);~/py_envs/hms/core/bin/python setup.py sdist
```

因此，当针对此`Makefile`执行`make dev`时，`dev`目标运行`unit_test`目标，然后使用`build_dir`目标创建项目的临时副本。之后，使用`dev_prep`处理文件名更改和其他环境的文件删除。然后才会执行剩余的`setup.py`。

# Python 虚拟环境

最后要解决的任务是确定是否要为各个组件项目使用 Python 虚拟环境，如有需要则创建它们，并记录如何创建它们，以便其他开发人员在需要时能够复制它们。

鉴于组件项目之间的结构、对它们的了解以及预期安装代码与其他系统成员的交互方式，显然没有必要为不同的环境建立，甚至没有明显的优势。只要在开发过程中充分注意和遵守，确保每个组件项目的`setup.py`或其他构建过程工件或配置中添加了依赖关系，最有可能出现的最坏情况是在执行测试安装的过程中发现缺少的依赖关系。在其他方面没有错误的实时安装中，可能会出现一些微不足道的低效率，例如`hms-gateway`项目可能会安装数据库或 GUI 库，它不需要或不使用，或者两个组件项目可能都安装了其他用户安装的消息系统库，但并不需要。

这些都不会对单个组件项目的操作构成任何即将发生的威胁，但它们确实会将不必要的代码引入到安装中。如果不仔细观察和管理，不必要的库安装可能会大量增加，这可能成为未来安全问题的一个因素。更糟糕的是，任何潜在的安全问题可能不会被视为结果；如果没有人真正意识到某个程序安装了不需要的东西，那么直到为时已晚才会得到修复。

为了确保系统安全，可以采取的第一步是确保它们只安装了必要的功能。这样做不会覆盖所有可能性，但会减少保持当前补丁和安全问题所需的带宽。

逐个项目跟踪依赖关系是虚拟环境可以发挥作用的地方。这是为每个项目单独设置它们的一个优点。另一个支持这种做法的观点是，一些平台，如各种公共云，将需要能够在其部署过程中包含依赖包的能力，而虚拟环境将把它们很好地与核心系统安装包集分开。在这方面，虚拟环境也是一种未来的保障。

因此，在开发`hms_sys`的情况下，我们将为每个组件项目设置一个单独的虚拟环境。如果以后证明它们是不必要的，它们总是可以被删除的。创建、激活和停用它们的过程非常简单，并且可以在任何方便的地方创建——实际上没有标准位置——命令因操作系统而异，如下所示：

| 虚拟环境活动 | 操作系统 |
| --- | --- |
| Linux/MacOS/Unix | Windows |
| 创建 | `python3 -m venv ~/path/to-myenv` | `c:\>c:\Python3\python -m venv c:\path\to\myenv` |
| 激活 | `source ~/path/to-myenv/bin/activate` | `C:\> c:\path\to\myenv\Scripts\activate.bat` |
| 停用 | `deactivate` | `C:\> c:\path\to\myenv\Scripts\deactivate.bat` |

创建和激活虚拟环境后，可以像在虚拟环境之外一样使用`pip`（或`pip3`）在其中安装包。安装的包存储在虚拟环境的库中，而不是全局系统库中。

记录哪些虚拟环境与哪些组件项目相关，只是将创建它所需的命令复制到项目级文档的某个地方。对于`hms_sys`，这些将存储在每个组件项目的`README.md`文件中。

让我们回顾一下这个故事的任务：

+   分析用例，逻辑和物理架构，以定义组件项目的需求和结构——**完成**

+   为每个已识别的组件项目构建标准项目起点——**完成**

+   为每个组件项目实施一个最小的`setup.py`文件，完成源包构建—**完成**

+   确定是否要为组件项目使用 Python 虚拟环境，实施它们，并记录如何重现它们—**完成**

+   提供一个单元测试结构

在上一章的最后指出，尽管已经设定了对所有代码进行单元测试的期望，并且所有模块和类的公共成员都受到了该要求的约束，但也指出尚未定义任何测试策略细节，这正是本次迭代中单元测试故事的重要部分：

+   作为开发人员，我需要知道如何以及在何处为代码库编写单元测试，以便在编写代码后创建单元测试。我还需要确保代码经过彻底测试：

1.  定义单元测试标准/要求（覆盖率、按类型的标准值等）

1.  实施一个机制来强制执行这些标准

1.  定义单元测试代码将存放在组件项目结构中的何处

1.  为每个组件项目实施一个基本的顶层测试，以确保没有任何失败

这些单元测试材料的大部分内容都是从 Python 2.7.x 代码转换和改编而来的，关于这一点的讨论可以在作者的博客上找到（从[bit.ly/HOSEP-IDIC-UT](http://bit.ly/HOSEP-IDIC-UT)开始）。尽管该代码是为较旧版本的 Python 编写的，但可能还可以从那里的单元测试文章中获得额外的见解。

可以说，应该测试所有成员，而不仅仅是公共成员——毕竟，如果涉及到的代码在任何地方被使用，那么就应该在可预测行为方面也要符合相同的标准，是吗？从技术上讲，没有理由不能这样做，特别是在 Python 中，受保护和私有类成员实际上并不受保护或私有——它们只是按照惯例被视为这样——在 Python 的早期版本中，受保护的成员是可以访问的，而私有成员（以两个下划线作为前缀：`__private_member`）在派生类中是不能直接访问的，除非通过它们的变形名称来调用。在 Python 3 中，尽管名称修饰仍在起作用，但在语言级别上不再强制执行名义上的受保护或私有范围。这很快就可以证明。考虑以下类定义：

```py
class ExampleParent:

    def __init__(self):
        pass

    def public_method(self, arg, *args, **kwargs):
        print('%s.public_method called:' % self.__class__.__name__)
        print('+- arg ...... %s' % arg)
        print('+- args ..... %s' % str(args))
        print('+- kwargs ... %s' % kwargs)

    def _protected_method(self, arg, *args, **kwargs):
        print('%s._protected_method called:' % self.__class__.__name__)
        print('+- arg ...... %s' % arg)
        print('+- args ..... %s' % str(args))
        print('+- kwargs ... %s' % kwargs)

    def __private_method(self, arg, *args, **kwargs):
        print('%s.__private_method called:' % self.__class__.__name__)
        print('+- arg ...... %s' % arg)
        print('+- args ..... %s' % str(args))
        print('+- kwargs ... %s' % kwargs)

    def show(self):
        self.public_method('example public', 1, 2, 3, key='value')
        self._protected_method('example "protected"', 1, 2, 3, key='value')
        self.__private_method('example "private"', 1, 2, 3, key='value')
```

如果我们创建`ExampleParent`的一个实例，并调用它的`show`方法，我们期望看到所有三组输出，这正是发生的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/2b1d4a55-d5ba-4906-a7da-27ee5dd81a70.png)

如果使用`dir(ExampleParent)`检查`ExampleParent`类结构，可以看到所有三种方法：['`_ExampleParent__private_method`', …, '`_protected_method`', '`public_method`', …]。在 Python 的早期版本中，从`ExampleParent`派生的类仍然可以访问`public_method`和`_protected_method`，但如果通过该名称调用`__private_method`，则会引发错误。在 Python 3（以及一些较新版本的 Python 2.7.x）中，情况已经不再是这样了。

```py
class ExampleChild(ExampleParent):
    pass
```

创建这个类的一个实例，并调用它的`show`方法会产生相同的结果：![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/24ed77f9-a8fd-49ac-a999-51d090e8aaa1.png)

从技术上讲，那么 Python 类的所有成员都是公共的。

那么，从定义单元测试策略的角度来看，如果所有类成员都是公共的，这意味着什么？如果遵守了公共/受保护/私有的约定，那么以下内容适用：

+   公共成员应该在与它们定义的类相对应的测试套件中进行测试（它们的原始类）

+   大多数受保护的成员可能打算被派生类继承，并且应该在与定义它们的类相对应的测试套件中进行深入测试

+   私有成员应该被视为真正的私有成员——在其原始类之外根本不可访问——或者被视为可能发生突发变化而无需警告的实现细节

+   继承成员不需要再次进行任何测试，因为它们已经针对其原始类进行了测试

+   从其父类重写的成员将在与其被重写的类相关的套件中进行测试

建立一个适用于所有这些规则的单元测试过程是可能的，尽管它相当复杂且足够实质性，以至于将其封装在某种可重复使用的函数或类中将非常有利，这样它就不必在每个测试过程中重新创建，或者在测试策略发生变化时在数十甚至数百个副本中进行维护。最终目标是拥有一个可重复的测试结构，可以快速轻松地实现，这意味着它也可以以与先前模块和包头部相同的方式进行模板化。

首先，我们需要一些东西来测试。具体来说，我们需要具有方法的类，这些方法属于先前指出的类别：

+   本地定义

+   从父类继承

+   从父类重写

这涵盖了所有公共/受保护/私有选项。虽然先前没有明确提到，但我们还应该包括一个至少有一个抽象方法的类。它们仍然是类，也需要进行测试；只是还没有被讨论过。它们不需要非常复杂来说明测试过程，尽管它们应该返回可测试的值。考虑到所有这些，这里是一组简单的类，我们将用它们来进行测试，并生成核心测试过程：

这些文件位于`hms_sys`代码库中，位于顶层`scratch-space`目录中。

```py
import abc

class Showable(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def show(self):
        pass

class Parent(Showable):

    _lead_len = 33

    def __init__(self, arg, *args, **kwargs):
        self.arg = arg
        self.args = args
        self.kwargs = kwargs

    def public(self):
        return (
            ('%s.arg [public] ' % self.__class__.__name__).ljust(
                self.__class__._lead_len, '.') + ' %s' % self.arg
            )

    def _protected(self):
        return (
            ('%s.arg [protected] ' % self.__class__.__name__).ljust(
                self.__class__._lead_len, '.') + ' %s' % self.arg
            )

    def __private(self):
        return (
            ('%s.arg [private] ' % self.__class__.__name__).ljust(
                self.__class__._lead_len, '.') + ' %s' % self.arg
            )

    def show(self):
        print(self.public())
        print(self._protected())
        print(self.__private())

class Child(Parent):
    pass

class ChildOverride(Parent):

    def public(self):
        return (
            ('%s.arg [PUBLIC] ' % self.__class__.__name__).ljust(
                self.__class__._lead_len, '.') + ' %s' % self.arg
            )

    def _protected(self):
        return (
            ('%s.arg [PROTECTED] ' % self.__class__.__name__).ljust(
                self.__class__._lead_len, '.') + ' %s' % self.arg
            )
```

```py
    def __private(self):
        return (
            ('%s.arg [PRIVATE] ' % self.__class__.__name__).ljust(
                self.__class__._lead_len, '.') + ' %s' % self.arg
            )
```

创建每个具体类的快速实例，并调用每个实例的`show`方法，显示预期的结果：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/76292447-5806-4101-acb0-c649c747d0ba.png)

# 基本单元测试

Python 中的单元测试由内置的`unittest`模块支持。可能还有其他模块也提供单元测试功能，但`unittest`是 readily available 的，它默认安装在 Python 虚拟环境中，并且至少作为起点，提供了我们所需的所有测试功能。先前类的初始测试模块非常简单，即使它除了定义适用于被测试代码的测试用例类之外，什么也没做：

```py
#!/usr/bin/env python

import unittest

class testShowable(unittest.TestCase):
    pass

class testParent(unittest.TestCase):
    pass

class testChild(unittest.TestCase):
    pass

class testChildOverride(unittest.TestCase):
    pass

unittest.main()
```

以`test`开头的每个类（并且派生自`unittest.TestCase`）将由模块末尾的`unittest.main()`调用实例化，并且这些类中以`test`开头的每个方法都将被执行。如果我们向其中一个添加测试方法，例如`testParent`，并按以下方式运行测试模块：

```py
class testParent(unittest.TestCase):
    def testpublic(self):
        print('### Testing Parent.public')
    def test_protected(self):
        print('### Testing Parent._protected')
    def test__private(self):
        print('### Testing Parent.__private')
```

可以看到测试方法的执行：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/8564487b-106a-4bdd-9069-98606419bd70.png)

如果`print()`调用被替换为`pass`，如下面的代码所示，输出会更简单，对于每个执行而不引发错误的测试用例的测试方法，会打印一个句点：

```py
class testParent(unittest.TestCase):
    def testpublic(self):
        pass
    def test_protected(self):
        pass
    def test__private(self):
        pass
```

执行时，会产生以下结果：![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/f2124f2f-1f61-400a-9028-6170a1628ac4.png)

到目前为止，一切都很顺利；我们有可以执行的测试，所以下一个问题是如何应用我们想要应用的测试策略规则。第一个策略，为每个源模块拥有一个测试模块，是项目结构的一个方面，而不是与测试执行流程相关的一个方面。为了解决这个问题，我们真正需要做的就是定义在任何给定项目中测试代码将存放的位置。由于我们知道我们将来会想要在构建过程中运行测试，我们需要有一个公共的测试目录，一个刚好在其中的文件（称之为`run_tests.py`）可以按需运行项目的所有测试，以及一个测试目录和文件结构，该结构对该文件应该是可访问的，这最终看起来像是`hms_core`组件项目的这样：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/e13fc4d7-5a42-4fd5-bde1-e66d4c44920d.png)

# 识别缺失的测试用例类

早些时候指出的测试目标的平衡都需要能够检查被测试的代码，以识别需要进行测试的模块成员，以及这些成员的成员。这可能听起来令人生畏，但 Python 提供了一个专门用于此目的的模块：`inspect`。它提供了一系列非常强大的函数，可以用于在运行时检查 Python 代码，这可以用来生成成员名称的集合，进而用于确定高级测试覆盖是否符合我们正在建立的标准。

为了说明，我们需要测试的前述类将被保存在一个名为`me.py`的模块中，这使它们可以被导入，每一步展示关于`me`模块的所需信息的过程都将被收集在`inspect_me.py`中，如此所示。相应的测试用例将存在于`test_me.py`中，它将首先作为一个几乎空白的文件开始——一开始不会在那里定义任何测试用例类。

第一步是识别我们将需要测试用例类的`me`的目标成员。就目前而言，我们所需要的只是目标模块中的类的列表，可以按如下方式检索：

```py
#!/usr/bin/env python

import inspect

import me as target_module

target_classes = set([
    member[0] for member in 
    inspect.getmembers(target_module, inspect.isclass)
])
# target_classes = {
#   'Child', 'ChildOverride', 'Parent', 'Showable'
# } at this point
```

一步一步，正在发生的是这样的：

1.  正在导入`inspect`模块。

1.  正在导入`me`模块，使用`target_module`作为其默认模块名的覆盖——我们希望能够保持导入的模块名称可预测且相对恒定，以便在以后更容易地重用，而这从这里开始。

1.  对`target_module`调用`inspect`的`getmembers`函数，使用`isclass`作为过滤谓词。这将返回一个类似`('ClassName', <class object>)`的元组列表。这些结果通过列表推导提取出只有类名的列表，并将该列表传递给 Python 的`set`，以产生发现的类名的正式集合。

Python 的`set`类型是一种非常有用的基本数据类型，它提供了一个可迭代的值集合，这些值是不同的（在集合中从不重复），并且可以与其他集合合并（使用`union`），从其他集合中删除其成员（使用`difference`），以及一系列其他操作，这些操作都符合标准集合理论的预期。

有了这些名称，创建一组预期的测试用例类名就很简单了：

```py
expected_cases = set([
    'test%s' % class_name 
    for class_name in target_classes
    ]
)
# expected_cases = {
#   'testChild', 'testShowable', 'testChildOverride', 
#   'testParent'
# } at this point
```

这只是另一个列表推导，它构建了一个以`test`开头的类名集合，从目标类名集合中。与收集目标模块中的类名的方法类似，可以用类似的方法找到存在于`test_me.py`模块中的测试用例类：

```py
import unittest

import test_me as test_module

test_cases = set([
    member[0] for member in 
    inspect.getmembers(test_module, inspect.isclass)
    if issubclass(member[1], unittest.TestCase)
])
# test_cases, before any TestCase classes have been defined, 
# is an empty set
```

除了对每个找到的成员进行`issubclass`检查，这将限制集合的成员为从`unittest.TestCase`派生的类的名称，这与构建初始`target_classes`集合的过程完全相同。现在我们有了收集预期和实际定义的内容的集合，确定需要创建的测试用例类是一个简单的事情，只需从预期的集合中删除已定义的测试用例名称：

```py
missing_tests = expected_cases.difference(test_cases)
# missing_tests = {
#   'testShowable', 'testChild', 'testParent', 
#   'testChildOverride'
# }
```

如果`missing_tests`不为空，则其名称集合代表需要创建的测试用例类名称，以满足“所有成员将被测试”的政策的第一部分。此时对结果的简单打印就足够了：

```py
if missing_tests:
    print(
        'Test-policies require test-case classes to be '
        'created for each class in the code-base. The '
        'following have not been created:\n * %s' % 
        '\n * '.join(missing_tests)
    )
```

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/0a3a9422-8343-452d-860f-528ac0c04b40.png)

已经确定了需要创建的缺失的测试用例类项，它们可以添加到`test_me.py`中：

```py
#!/usr/bin/env python

import unittest

class testChild(unittest.TestCase):
    pass

class testChildOverride(unittest.TestCase):
    pass

class testParent(unittest.TestCase):
    pass

class testShowable(unittest.TestCase):
    pass

if __name__ == '__main__':
    unittest.main()
```

一旦它们被添加（并且一旦从`unittest.TestCase`派生出子类，因为之前执行了识别实际测试用例类的检查），就不再有需要解决的缺失的测试用例。

类似的方法也可以用于识别应该进行测试的模块级函数——毕竟，它们也是模块的公共成员，而政策关注的正是模块的公共成员。对函数或任何其他可调用元素进行测试的实际实现将遵循稍后为类方法建立的结构和过程。

实际上，可能无法轻松使用这种类型的过程识别的唯一公共成员是未受管理的属性——在模块级别创建的模块常量或变量。尽管这些仍然可以进行测试，并且可以说应该进行测试，但它们是未受管理的，可以在运行时更改，而没有任何检查来确保它们不会在后续某个地方出现问题，这可能会使围绕它们的任何正式测试政策几乎成为一种浪费时间。也就是说，测试它们并没有坏处，即使只是为了确保对它们的更改（有意或意外的）不会被忽视并在以后引发问题和错误。

# 识别缺失的测试方法

之前用于识别模块中的类的`inspect.getmembers`函数也可以用于识别其他目标元素的其他成员类型，例如类的属性和方法。识别任一成员的过程与之前已经展示的识别模块中的类的过程类似，看起来像这样（对于属性）：

```py
target_class = target_module.Parent

target_properties = set([
    member[0] for member in 
    inspect.getmembers(target_class, inspect.isdatadescriptor)
])
# target_properties = {'__weakref__'}
```

与在模块中查找类的过程的唯一显著差异是被检查的目标（在这种情况下是`target_class`，我们已将其设置为`Parent`类）和谓词（`inspect.isdatadescriptor`），它将结果过滤为数据描述符——受控属性或正式属性。

在第六章 *开发工具和最佳实践*中，当讨论和定义各种内部代码标准时，注意到使用受控属性/属性的一个重要方面是对于单元测试目的的重要性：知道为任何给定属性测试的值类型。这是采用这种方法的另一个优势：使用内置的`property()`函数定义的类属性可以被检测为需要测试的类成员。尽管未受管理的属性可能是可检测的，但可能不容易识别为需要测试的类的成员，并且几乎可以肯定这种识别几乎肯定不是可以自动化的。

类似的`inspect.getmembers`调用可以用于识别类方法：

```py
target_functions = set([
    member[0] for member in 
    inspect.getmembers(target_class, inspect.isfunction)
])
target_methods = set([
    member[0] for member in 
    inspect.getmembers(target_class, inspect.ismethod)
])
target_methods = target_methods.union(target_functions)
# target_methods = {
#   '_Parent__private', 'public', 'show', 
#   '_protected', '__init__'
# }
```

这两个成员名称集合都包括测试策略不要求测试的项目，尽管`__weakref__`属性是所有类的内置属性，而`_Parent__private`方法条目与我们最初的`__private`方法相关联，这两者都不需要包含在我们所需测试方法的列表中。通过简单地添加对属性列表名称中前导`__`的检查，可以实现一些基本的过滤（因为根据我们的测试策略，我们永远不会测试私有属性）。这将处理掉测试列表中的`__weakref__`，并允许公共和受保护的属性出现。

在向`Parent`添加属性声明（`prop`）并添加过滤条件后，我们将得到以下结果：

```py
target_properties = set([
    member[0] for member in 
    inspect.getmembers(target_class, inspect.isdatadescriptor)
    if not member[0].startswith('__')
])
# target_properties = {'prop'}
```

然而，同样的方法并不适用于查找需要测试的类方法；一些常见的方法，比如`__init__`，其名称会基于名称进行过滤，但是我们希望确保需要测试的成员。这种简单的基于名称的过滤也无法处理不包括在类中但在该类中没有定义的成员名称，比如`Child`类的所有属性和成员。虽然基于名称的过滤是朝着正确方向迈出的一步，但感觉是时候退一步，看看更广泛的解决方案，一个能考虑成员定义位置的解决方案。

这涉及以更复杂的方式构建测试名称列表，并注意每个类的**方法解析顺序**（**MRO**），这可以在类的内置`__mro__`属性中找到。我们将从定义一个空集开始，并获取类的 MRO，然后获取与目标类相同的属性名称列表：

```py
property_tests = set()
sourceMRO = list(target_class.__mro__)
sourceMRO.reverse()
# Get all the item's properties
properties = [
    member for member in inspect.getmembers(
        target_class, inspect.isdatadescriptor)
    if member[0][0:2] != '__'
]
# sourceMRO = [
#   <class 'object'>, <class 'me.Showable'>, 
#   <class 'me.Parent'>
# ]
```

我们还需要跟踪属性的定义位置，即它来自哪个类，以及属性的实际实现。我们希望从每个完整的数据结构开始，将名称与源类和最终实现关联起来，但最初用`None`值初始化。这将允许最终的结构在填充后用于识别类的成员，这些成员在那里没有定义：

```py
propSources = {}
propImplementations = {}
for name, value in properties:
    propSources[name] = None
    propImplementations[name] = None
# Populate the dictionaries based on the names found
for memberName in propSources:
    implementation = target_class.__dict__.get(memberName)
    if implementation and propImplementations[memberName] != implementation:
        propImplementations[memberName] = implementation
        propSources[memberName] = target_class
# propImplementations = {
#   "prop": <property object at 0x7fa2f0edeb38>
# }
# propSources = {
#   "prop": <class 'me.Parent'>
# }
# If the target_class is changed to target_module.Child:
# propImplementations = {
#   "prop": None    # Not set because prop originates in Parent
# }
# propSources = {
#   "prop": None    # Also not set for the same reason
# }
```

有了这些数据，生成所需属性测试方法列表与之前显示的所需测试用例类列表类似：

```py
property_tests = set(
    [
        'test%s' % key for key in propSources 
        if propSources[key] == target_class
    ]
)
# property_tests = {'testprop'}
# If the target_class is changed to target_module.Child:
# property_tests = set()
```

获取和筛选类的方法成员的过程几乎相同，尽管我们将包括所有成员，甚至是以`__`开头的成员，并获取函数或方法，以确保包括类和静态方法。

```py
method_tests = set()
sourceMRO = list(target_class.__mro__)
sourceMRO.reverse()
# Get all the item's methods
methods = [
    member for member in inspect.getmembers(
        target_class, inspect.isfunction)
] + [
    member for member in inspect.getmembers(
        target_class, inspect.ismethod)
]
```

用于跟踪方法源和实现的`dict`项的构建过程可以主动跳过本地、私有成员以及已定义为抽象的成员：

```py
methSources = {}
methImplementations = {}
for name, value in methods:
    if name.startswith('_%s__' % target_class.__name__):
        # Locally-defined private method - Don't test it
        continue
    if hasattr(value, '__isabstractmethod__') and value.__isabstractmethod__:
        # Locally-defined abstract method - Don't test it
        continue
    methSources[name] = None
    methImplementations[name] = None
```

测试名称列表生成的平衡是相同的：

```py
method_tests = set(
    [
        'test%s' % key for key in methSources 
        if methSources[key] == target_class
    ]
)
# method_tests = {
#   'testpublic', 'test__init__', 'test_protected', 
#   'testshow'
# }
# If the target_class is changed to target_module.Child:
# method_tests = set()
# If the target_class is changed to target_module.Showable:
# method_tests = set()
```

那么，从所有这些探索中得出了什么结论？简而言之，它们如下：

+   可以自动化检测模块的成员应该需要创建测试用例

+   虽然可以自动化验证所需的测试用例是否存在于与给定源模块对应的测试模块中，但仍需要一些纪律来确保创建测试模块

+   可以自动化检测对于任何给定的测试用例/源类组合需要哪些测试方法，并且可以在不需要测试私有和抽象成员的情况下进行

尽管这是相当多的代码。大约 80 行，没有一些实际测试类成员和问题公告，以及剥离所有注释后。这比应该被复制和粘贴的代码要多得多，尤其是对于具有高破坏潜力或影响的流程。最好能够将所有内容都保存在一个地方。幸运的是，`unittest`模块的类提供了一些选项，可以使逐模块的代码覆盖测试变得非常容易——尽管这将首先需要一些设计和实现。

# 创建可重用的模块代码覆盖测试

一个良好的单元测试框架不仅允许为代码元素的成员创建测试，还提供了在运行任何测试之前以及在所有测试执行成功或失败后执行代码的机制。Python 的`unittest`模块在各个`TestCase`类中处理这一点，允许类实现`setUpClass`和`tearDownClass`方法来分别处理测试前和测试后的设置和拆卸。

这意味着可以创建一个测试类，该类可以被导入，扩展具有特定于模块的属性，并添加到测试模块中，该测试模块可以利用刚刚显示的所有功能来执行以下操作：

+   查找目标模块中的所有类和函数

+   确定测试模块中需要存在哪些测试用例类，并测试它们以确保它们存在

+   确定每个源模块成员的测试用例类需要存在哪些测试，以满足我们的单元测试政策和标准。

+   检查这些测试方法是否存在

代码覆盖测试用例类将需要知道要检查哪个模块以找到所有信息，但它应该能够自行管理其他所有内容。最终，它将定义自己的一个测试，以确保源模块中的每个类或函数在测试模块中都有一个相应的测试用例类：

```py
def testCodeCoverage(self):
    if not self.__class__._testModule:
        return
    self.assertEqual([], self._missingTestCases, 
        'unit testing policies require test-cases for all classes '
        'and functions in the %s module, but the following have not '
        'been defined: (%s)' % (
            self.__class__._testModule.__name__, 
            ', '.join(self._missingTestCases)
        )
    )
```

它还需要能够提供一种机制，以允许检查属性和方法测试方法。如果可以实现的话，以完全自动化的方式进行这样的检查是很诱人的，但可能有些情况会比值得的麻烦。至少目前，通过创建一些装饰器来使这些测试附加到任何给定的测试用例类变得容易，这些测试将被添加到可用的测试中。

Python 的装饰器本身是一个相当详细的主题。现在，不要担心它们是如何工作的，只要知道它们的使用方式，并相信它们是有效的。

我们的起点只是一个从`unittest.TestCase`派生的类，该类定义了前面提到的`setUpClass`类方法，并对定义的类级`_testModule`属性进行了一些初始检查——如果没有测试模块，那么所有测试应该简单地跳过或通过，因为没有任何被测试的内容：

```py
class ModuleCoverageTest(unittest.TestCase):
    """
A reusable unit-test that checks to make sure that all classes in the 
module being tested have corresponding test-case classes in the 
unit-test module where the derived class is defined.
"""
@classmethod
def setUpClass(cls):
    if not cls._testModule:
        cls._missingTestCases = []
        return
```

`@classmethod`行是内置的类方法装饰器。

我们需要首先找到目标模块中所有可用的类和函数：

```py
cls._moduleClasses = inspect.getmembers(
     cls._testModule, inspect.isclass)
cls._moduleFunctions = inspect.getmembers(
     cls._testModule, inspect.isfunction)
```

我们将跟踪被测试模块的名称作为类和函数成员的额外检查标准，以防万一：

```py
cls._testModuleName = cls._testModule.__name__
```

跟踪类和函数测试的机制类似于初始探索中的源和实现字典：

```py
cls._classTests = dict(
   [
       ('test%s' % m[0], m[1]) 
       for m in cls._moduleClasses
       if m[1].__module__ == cls._testModuleName
   ]
)
cls._functionTests = dict(
   [
       ('test%s' % m[0], m[1]) 
       for m in cls._moduleFunctions
       if m[1].__module__ == cls._testModuleName
   ]
)
```

所需测试用例类名称的列表是所有类和函数测试用例类名称的聚合列表：

```py
cls._requiredTestCases = sorted(
   list(cls._classTests.keys()) + list(cls._functionTests.keys())
)
```

实际测试用例类的集合将稍后用于测试：

```py
cls._actualTestCases = dict(
    [
      item for item in 
      inspect.getmembers(inspect.getmodule(cls), 
      inspect.isclass) 
    if item[1].__name__[0:4] == 'test'
       and issubclass(item[1], unittest.TestCase)
    ]
)
```

接下来，我们将生成缺少的测试用例名称列表，该列表由类`testCodeCoverage`测试方法使用：

```py
cls._missingTestCases = sorted(
   set(cls._requiredTestCases).difference(
       set(cls._actualTestCases.keys())))
```

此时，该单独的测试方法将能够执行，并且会输出指示缺少哪些测试用例的输出。如果我们将`test_me.py`模块写成如下形式：

```py
from unit_testing import ModuleCoverageTest

class testmeCodeCoverage(ModuleCoverageTest):
    _testModule = me

if __name__ == '__main__':
    unittest.main()
```

然后在执行后，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/9c2a3323-b640-4cec-b3ee-6065dc67fc9b.png)

要使顶层代码覆盖测试通过，只需添加缺少的测试用例类：

```py
class testmeCodeCoverage(ModuleCoverageTest):
    _testModule = me

class testChild(unittest.TestCase):
    pass

class testChildOverride(unittest.TestCase):
    pass

class testParent(unittest.TestCase):
    pass

class testShowable(unittest.TestCase):
    pass

if __name__ == '__main__':
    unittest.main()
```

这种以主动方式确保代码覆盖率的方法非常适合使单元测试变得不那么麻烦。如果编写测试的过程始于一个通用测试，该测试将告诉测试开发人员在每一步中缺少了什么，那么编写测试的整个过程实际上就是重复以下步骤，直到没有测试失败为止：

+   执行测试套件

+   如果有测试失败，进行必要的代码更改以使最后一个测试通过。

+   如果是缺少测试失败，添加必要的测试类或方法

+   如果是因为源代码中的代码而失败，请在验证所涉及的测试值应该通过后相应地更改

继续前进！

为了能够测试测试模块中所有测试用例类中缺少的属性和方法测试，我们需要找到它们并按类进行跟踪。这基本上与我们之前发现的过程相同，但存储的值必须能够按类名检索，因为我们希望单个覆盖测试实例检查所有源代码和测试用例类，因此我们将它们存储在两个字典中，`propSources`用于每个的源，`propImplementations`用于实际的功能对象：

```py
cls._propertyTestsByClass = {}
for testClass in cls._classTests:
    cls._propertyTestsByClass[testClass] = set()
    sourceClass = cls._classTests[testClass]
    sourceMRO = list(sourceClass.__mro__)
    sourceMRO.reverse()
    # Get all the item's properties
    properties = [
         member for member in inspect.getmembers(
               sourceClass, inspect.isdatadescriptor)
            if member[0][0:2] != '__'
         ]
    # Create and populate data-structures that keep track of where 
    # property-members originate from, and what their implementation 
    # looks like. Initially populated with None values:
    propSources = {}
    propImplementations = {}
    for name, value in properties:
        propSources[name] = None
        propImplementations[name] = None
     for memberName in propSources:
        implementation = sourceClass.__dict__.get(memberName)
        if implementation \
           and propImplementations[memberName] != implementation:
               propImplementations[memberName] = implementation
               propSources[memberName] = sourceClass
         cls._propertyTestsByClass[testClass] = set(
            [
               'test%s' % key for key in propSources 
               if propSources[key] == sourceClass
            ]
)
```

方法测试的获取方式与之前的探索方式相同：

```py
cls._methodTestsByClass = {}
for testClass in cls._classTests:
    cls._methodTestsByClass[testClass] = set()
    sourceClass = cls._classTests[testClass]
    sourceMRO = list(sourceClass.__mro__)
    sourceMRO.reverse()
# Get all the item's methods
methods = [
   member for member in inspect.getmembers(
          sourceClass, inspect.ismethod)
   ] + [
   member for member in inspect.getmembers(
          sourceClass, inspect.isfunction)
   ]
# Create and populate data-structures that keep track of where 
# method-members originate from, and what their implementation 
# looks like. Initially populated with None values:
methSources = {}
methImplementations = {}
for name, value in methods:
    if name.startswith('_%s__' % sourceClass.__name__):
       # Locally-defined private method - Don't test it
         continue
    if hasattr(value, '__isabstractmethod__') \
       and value.__isabstractmethod__:
       # Locally-defined abstract method - Don't test it
         continue                methSources[name] = None
       methImplementations[name] = None
  for memberName in methSources:
       implementation = sourceClass.__dict__.get(memberName)
          if implementation \
             and methImplementations[memberName] != implementation:
             methImplementations[memberName] = implementation
             methSources[memberName] = sourceClass
   cls._methodTestsByClass[testClass] = set(
        [
            'test%s' % key for key in methSources 
            if methSources[key] == sourceClass
        ]
)
```

一旦执行了最后两个代码块，代码覆盖测试类将完整地列出测试模块中每个测试用例类所需的所有测试方法。属性测试集合（`cls._propertyTestsByClass`）是稀疏的，因为与任何类相关联的属性只有一个，即`Parent.prop`：

```py
{
    "testChild": set(),
    "testChildOverride": set(),
    "testParent": {"testprop"},
    "testShowable": set()
}
```

方法测试结构（`cls._methodTestsByClass`）有更多内容，准确地表示了`ChildOverride`类中的`public`和`_protected`方法需要它们自己的测试方法，并且`Showable`中的抽象`show`方法不需要被测试：

```py
{
    "testChild": set(),
    "testChildOverride": {
        "test_protected", "testpublic"
    },
    "testParent": {
        "test__init__", "test_protected", 
        "testpublic", "testshow"
    },
    "testShowable": set()
}
```

这些数据是处理所需属性和方法测试的所有内容。剩下的就是想出一种方法将它们附加到每个测试用例类上。

# 属性和方法测试装饰器

装饰器可以被视为接受另一个函数作为参数，并在装饰的函数周围扩展或包装其他功能的函数，而不实际修改它。任何可调用的东西——函数、类的实例方法或（在本例中）属于类的类方法——都可以用作装饰函数。在这种情况下，代码覆盖测试用例类将使用装饰器函数结构定义两个类方法（`AddPropertyTesting`和`AddMethodTesting`），以便向使用它们进行装饰的任何类添加新方法（`testPropertyCoverage`和`testMethodCoverage`）。由于这两个方法是主代码覆盖类的嵌套成员，它们可以访问类中的数据，特别是生成的所需属性和方法测试名称列表。此外，因为它们是装饰函数本身的嵌套成员，它们将可以访问这些方法中的变量和数据。

这两个装饰器方法几乎是相同的，除了它们的名称、消息和它们查找数据的位置，因此只详细介绍第一个`AddMethodTesting`。该方法首先检查以确保它是`ModuleCoverageTest`类的成员，这确保了它要查看的数据仅限于与源代码和测试模块相关的数据：

```py
@classmethod
def AddMethodTesting(cls, target):
    if cls.__name__ == 'ModuleCoverageTest':
        raise RuntimeError('ModuleCoverageTest should be extended '
            'into a local test-case class, not used as one directly.')
    if not cls._testModule:
        raise AttributeError('%s does not have a _testModule defined '
          'as a class attribute. Check that the decorator-method is '
          'being called from the extended local test-case class, not '
          'from ModuleCoverageTest itself.' % (cls.__name__))
```

函数开始时传入的`target`参数是一个`unittest.TestCase`类（尽管它没有明确进行类型检查）。

它还需要确保要使用的数据是可用的。如果不可用，无论出于什么原因，都可以通过显式调用刚刚定义的`setUpClass`方法来解决：

```py
try:
   if cls._methodTestsByClass:
      populate = False
    else:
        populate = True
except AttributeError:
    populate = True
if populate:
    cls.setUpClass()
```

下一步是定义一个函数实例来实际执行测试。这个函数被定义得好像它是类的成员，因为在装饰过程完成时它将成为类的成员，但因为它嵌套在装饰器方法内部，所以它可以访问并保留到目前为止在装饰器方法中定义的所有变量和参数的值。其中最重要的是`target`，因为它将被装饰的类。`target`值本质上附加到正在定义/创建的函数上：

```py
def testMethodCoverage(self):
    requiredTestMethods = cls._methodTestsByClass[target.__name__]
    activeTestMethods = set(
      [
          m[0] for m in 
          inspect.getmembers(target, inspect.isfunction)
          if m[0][0:4] == 'test'
      ]
    )
    missingMethods = sorted(
        requiredTestMethods.difference(activeTestMethods)
    )
    self.assertEquals([], missingMethods, 
        'unit testing policy requires test-methods to be created for '
        'all public and protected methods, but %s is missing the '
        'following test-methods: %s' % (
        target.__name__, missingMethods
    )
)
```

测试方法本身非常简单：它创建了一组活动的测试方法名称，这些名称在附加到的测试用例类中被定义，然后从覆盖测试类中检索到的测试用例类的必需测试方法中移除这些名称，如果还有剩余的，测试将失败并宣布缺少了什么。

剩下的就是将函数附加到目标上并返回目标，以便不会中断对它的访问：

```py
target.testMethodCoverage = testMethodCoverage
return target
```

一旦这些装饰器被定义，它们就可以像这样应用于单元测试代码：

```py
class testmeCodeCoverage(ModuleCoverageTest):
    _testModule = me

@testmeCodeCoverage.AddPropertyTesting
@testmeCodeCoverage.AddMethodTesting
class testChild(unittest.TestCase):
    pass

@testmeCodeCoverage.AddPropertyTesting
@testmeCodeCoverage.AddMethodTesting
class testChildOverride(unittest.TestCase):
    pass

@testmeCodeCoverage.AddPropertyTesting
@testmeCodeCoverage.AddMethodTesting
class testParent(unittest.TestCase):
    pass

@testmeCodeCoverage.AddPropertyTesting
@testmeCodeCoverage.AddMethodTesting
class testShowable(unittest.TestCase):
    pass
```

有了它们，测试运行开始报告缺少了什么：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/4f0e03da-20e0-492e-bf6c-1734514a639c.png)

# 创建单元测试模板文件

刚刚显示的测试集合的最基本起点将作为任何其他关注单个模块的测试集合的起点。然而，`hms_sys`的预期代码结构包括整个代码包，并且可能包括这些包内的包。我们还不知道，因为我们还没有到那一步。这将对最终的单元测试方法产生影响，以及对模板文件的创建产生影响，以使得创建这些测试模块更快速和更少出错。

主要影响集中在这样一个想法上，即我们希望能够通过单个调用执行整个项目的所有测试，同时在组件项目的测试套件中不需要执行每个测试的情况下，只需运行一个或多个测试以针对包结构中更深层次的内容。因此，将测试按照与它们正在测试的包相同类型的组织结构进行拆分，并允许在任何级别的测试模块调用或被父级模块导入时导入子测试。

为此，单元测试模板模块需要适应与主代码库相同类型的导入功能，同时跟踪由测试运行发起的任何导入过程产生的所有测试。幸运的是，`unittest`模块还提供了可以用来管理这种需求的类，例如`TestSuite`类，它是可以执行的测试集合，并且可以根据需要向其添加新测试。最终的测试模块模板看起来很像我们之前创建的模块模板，尽管它以一些搜索和替换的样板注释开头：

```py
#!/usr/bin/env python

# Python unit-test-module template. Copy the template to a new
# unit-test-module location, and start replacing names as needed:
#
# PackagePath  ==> The path/namespace of the parent of the module/package
#                  being tested in this file.
# ModuleName   ==> The name of the module being tested
#
# Then remove this comment-block

"""
Defines unit-tests for the module at PackagePath.ModuleName.
"""

#######################################
# Any needed from __future__ imports  #
# Create an "__all__" list to support #
#   "from module import member" use   #
#######################################
```

与提供应用功能的包和模块不同，单元测试模块模板不需要提供太多的`**all**`条目，只需要提供模块本身中的测试用例类和任何子测试模块：

```py
__all__ = [
    # Test-case classes
    # Child test-modules
]
```

所有测试模块中都会发生一些标准导入，并且还可能存在第三方导入的可能性，尽管这可能不太常见：

```py
#######################################
# Standard library imports needed     #
#######################################

import os
import sys
import unittest

#######################################
# Third-party imports needed          #
#######################################

#######################################
# Local imports needed                #
#######################################

from unit_testing import *

#######################################
# Initialization needed before member #
#   definition can take place         #
#######################################
```

所有的测试模块都将定义一个名为`LocalSuite`的`unittest.TestSuite`实例，其中包含所有本地测试用例，并且在需要时可以在父模块中按名称导入：

```py
#######################################
# Module-level Constants              #
#######################################

LocalSuite = unittest.TestSuite()

#######################################
# Import the module being tested      #
#######################################

import PackagePath.ModuleName as ModuleName
```

我们还将定义一些样板代码，用于定义代码覆盖测试用例类：

```py
#######################################
# Code-coverage test-case and         #
# decorator-methods                   #
#######################################

class testModuleNameCodeCoverage(ModuleCoverageTest):
    _testModule = ModuleName

LocalSuite.addTests(
    unittest.TestLoader().loadTestsFromTestCase(
        testModuleNameCodeCoverage
   )
)
```

从这一点开始，除了模块的`__main__`执行之外的所有内容都应该是测试用例类的定义：

```py
#######################################
# Test-cases in the module            #
#######################################

#######################################
# Child-module test-cases to execute  #
#######################################
```

如果以后需要导入子测试模块，这里有用于执行此操作的代码结构，已注释并准备好复制、粘贴、取消注释和根据需要重命名：

```py
# import child_module
# LocalSuite.addTests(child_module.LocalSuite._tests)
```

还有更多标准模块部分，遵循标准模块和包模板的组织结构：

```py
#######################################
# Imports to resolve circular         #
# dependencies. Avoid if possible.    #
#######################################

#######################################
# Initialization that needs to        #
# happen after member definition.     #
#######################################

#######################################
# Code to execute if file is called   #
# or run directly.                    #
#######################################
```

最后，还有一些用于直接执行模块、运行测试并在没有失败时显示和写出报告的准备：

```py
if __name__ == '__main__':
    import time
    results = unittest.TestResult()
    testStartTime = time.time()
    LocalSuite.run(results)
    results.runTime = time.time() - testStartTime
    PrintTestResults(results)
    if not results.errors and not results.failures:
        SaveTestReport(results, 'PackagePath.ModuleName',
            'PackagePath.ModuleName.test-results')
```

模板提供了一些可以在首次复制到最终测试模块时找到并替换的项目：

+   `PackagePath`：被测试模块的完整命名空间，减去模块本身。例如，如果为一个完整命名空间为`hms_core.business.processes.artisan`的模块创建了一个测试模块，`PackagePath`将是`hms_core.business.processes`

+   `ModuleName`：被测试的模块的名称（使用前面的例子中的`artisan`）

搜索和替换操作还将为嵌入在模板中的`ModuleCoverageTest`子类定义提供一个唯一的名称。一旦这些替换完成，测试模块就可以运行，就像前面的例子中所示的那样，并且将开始报告缺少的测试用例和方法。

遵循这种结构的每个测试模块都在一个`unittest.TestSuite`对象中跟踪其本地测试，该对象可以被父测试模块导入，并且可以根据需要从子`TestSuite`实例中添加测试，模板文件中有一个注释掉的示例，显示了这种情况的样子：

```py
# import child_module
# LocalSuite.addTests(child_module.LocalSuite._tests)
```

最后，模板文件利用了自定义的`unit_testing`模块中定义的一些显示和报告函数，将总结的测试结果数据写入控制台，并且（当测试运行时没有失败）写入一个本地文件，如果需要的话可以在源代码控制中进行跟踪。

# 将测试与构建过程集成

只剩下一个故事/任务集，即如何将单元测试与组件项目的任何构建过程集成起来：

+   作为开发人员，我需要知道如何将组件项目的单元测试集成到该组件项目的构建过程中，以便构建可以自动执行单元测试：

+   确定如何将单元测试集成到构建过程中

+   确定如何处理不同环境的构建/测试集成

在组件项目中刚刚定义的单元测试结构中，将它们集成到构建过程中相对容易。在基于`setup.py`文件的构建中，测试模块可以在`setup`函数的`test_suite`参数中指定，并且可以通过执行`python setup.py test`来运行测试。在`hms_sys`组件项目中，还需要将单元测试标准代码的路径添加到`setup.py`中：

```py
#!/usr/bin/env python

# Adding our unit testing standards
import sys
sys.path.append('../standards')

from setuptools import setup

# The actual setup function call:
setup(
    name='HMS-Core',
    version='0.1.dev0',
    author='Brian D. Allbee',
    description='',
    package_dir={
        '':'src',
        # ...
    },
    # Can also be automatically generated using 
    #     setuptools.find_packages...
    packages=[
        'hms_core',
        # ...
    ],
    package_data={
#        'hms_core':[
#            'filename.ext',
#            # ...
#        ]
    },
    entry_points={
#        'console_scripts':[
#            'executable_name = namespace.path:function',
#            # ...
#        ],
    },
# Adding the test suite for the project
    test_suite='tests.test_hms_core',
)
```

如果需要基于 Makefile 的构建过程，`setup.py test`的具体调用可以简单地包含在相关的 Make 目标中：

```py
# Makefile for the HMS Core (hms-core) project

main: test setup
        # Doesn't (yet) do anything other than running the test and 
        # setup targets

setup:
        # Calls the main setup.py to build a source-distribution
        # python setup.py sdist

test:
        # Executes the unit-tests for the package, allowing the build-
        # process to die and stop the build if a test fails
        python setup.py. test
```

从`setup.py`中执行的测试套件将返回适当的值，以阻止 Make 进程在出现错误或失败时停止。

# 摘要

除了设置新团队或新业务之外，大多数这些流程和政策很可能在项目开始之前就已经建立好了——通常是在团队承担的第一个项目之前或期间。大多数开发商和团队都会发现这一章节中提出的解决方案的需求，并且会采取行动。

所有这些项目都已经设置并提交到版本控制系统，为随后的迭代开发工作奠定了基础。第一个“真正的”迭代将着手处理基本业务对象的定义和实现。


# 第八章：创建业务对象

在第七章中检查`hms_sys`的逻辑架构，*设置项目和流程*，整个系统范围内出现了一些常见的业务对象类型：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/253f3c63-fe1e-4bb4-80cc-0b2ae4bba3fd.png)

如前图所示的对象，解释如下：

+   一个**Artisan**对象代表一个**Artisan**——一个最终用户，他创建要出售的产品项目，并通过系统将这些产品提供给 HMS 中央办公室。**Artisans**被收集在中央办公室的数据结构中，并且在一定程度上可以由中央办公室工作人员管理，但是他们的实际数据大部分需要由个体工匠自己拥有和管理；这样，他们可以尽可能地控制自己的信息，中央办公室工作人员不必管理工匠的数据更改，例如，如果他们更改地址，或者想要添加或更改公司名称。

+   **产品**是一个物理对象的表示，是工匠创造并出售的物品。

+   订单是顾客通过 HMS 网店订购产品的结果。

这三种对象类型还暗示了另外两种之前没有提到的对象类型：

+   代表实际下订单的顾客，并且可以附加到一个或多个订单

+   **地址**，代表可以发货或收货的物理位置，也可以附加到一个或多个订单，可能是**顾客**的属性，几乎肯定是**工匠**的属性

本章将介绍将这些对象实现为通用类库的实现，该类库可以被应用程序和服务项目的代码利用，包括设计、实现、自动化测试和构建过程，将其转化为可部署的包。

本章涵盖以下内容：

+   迭代目标

+   故事和任务的组装

+   类的快速审查

+   在`hms_sys`中实现基本业务对象

+   测试业务对象

+   分发和安装考虑

+   质量保证和验收

+   操作/使用、维护和停用考虑

# 迭代目标

因此，这次迭代的交付成果是一个类库，可以与真实项目的包和代码一起安装或合并，用户应用程序和服务可以提供这些业务对象的通用表示结构：

+   `hms_core`包/库

+   单元测试

+   能够作为独立包构建

+   包括提供以下基本表示的基类：

+   +   工匠

+   顾客

+   订单

+   产品

# 故事和任务的组装

由于业务对象包的组件旨在被系统中的其他包消耗或使用，因此大部分相关故事仍然专注于提供开发人员需要的东西：

+   作为开发人员，我需要一个通用的定义和功能结构来表示系统中的地址，以便我可以将它们合并到需要它们的系统部分中：

+   定义`BaseAddress`抽象基类（ABC）

+   实现`BaseAddress` ABC

+   对`BaseAddress` ABC 进行单元测试

+   作为开发人员，我需要一个通用的定义和功能结构来表示系统中的工匠，以便我可以将它们合并到需要它们的系统部分中：

+   定义`BaseArtisan` ABC

+   实现`BaseArtisan` ABC

+   对`BaseArtisan` ABC 进行单元测试

+   作为开发人员，我需要一个通用的定义和功能结构来表示系统中的顾客，以便我可以将它们合并到需要它们的系统部分中：

+   定义`BaseCustomer` ABC

+   实现`BaseCustomer` ABC

+   对`BaseCustomer` ABC 进行单元测试

+   作为开发人员，我需要一个通用的定义和功能结构来表示系统中的订单，以便我可以将它们合并到需要它们的系统部分中：

+   定义一个`BaseOrder` ABC

+   实现`BaseOrder` ABC

+   对`BaseOrder` ABC 进行单元测试

+   作为开发人员，我需要一个通用的定义和功能结构来表示系统中的产品，以便我可以将它们合并到需要它们的系统部分中：

+   定义一个`BaseProduct` ABC

+   实现`BaseProduct` ABC

+   对`BaseProduct` ABC 进行单元测试

+   作为**Artisan**，我需要将业务对象库与我的应用程序一起安装，以便应用程序能够按需工作，而无需我安装它的依赖组件：

+   确定`setup.py`是否可以基于包含来自本地项目结构之外的包，并在可以的情况下实现它

+   否则，实现基于`Makefile`的过程，将`hms_core`包含在其他项目的打包过程中

+   作为中央办公室用户，我需要将业务对象库与我的应用程序一起安装，以便应用程序能够按需工作，而无需我安装它的依赖组件：

+   验证**Artisan**打包/安装过程是否也适用于中央办公室的安装

+   作为系统管理员，我需要安装业务对象库与**Artisan**网关服务，以便它能够按需工作，而无需我安装它的依赖组件：

+   验证**Artisan**打包/安装过程是否也适用于**Artisan**网关安装

值得注意的是，虽然这种设计从定义了许多抽象类开始，但这并不是唯一的方式。另一个可行的选择是从每个其他库中的简单 Concrete Classes 开始，然后提取这些类的共同要求，并创建 ABC 来强制执行这些要求。这种方法会更快地产生具体的功能，同时将结构和数据标准推迟到后面，并要求将相当多的代码从 Concrete Classes 移回到 ABC，但这仍然是一个可行的选择。

# 快速审查类

在任何面向对象的语言中，类都可以被视为创建对象的蓝图，定义了这些对象作为类的实例的特征、拥有的东西以及可以做的事情。类经常代表现实世界的对象，无论是人、地方还是物品，但即使它们不是，它们也提供了一套简洁的数据和功能/功能，适合逻辑概念单元。

随着`hms_sys`的开发进展，将设计和实现几个类，包括具体类和抽象类。在大多数情况下，设计将从类图开始，即一对多类的绘图，显示每个类的结构以及它们之间的任何关系：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/8a4d1e52-b870-4add-bea0-2cba58b74892.png)

**Concrete Class**旨在被实例化，从提供的蓝图创建对象实例。**Abstract Class**为具有特定**Class Members**（具体或抽象）的对象提供基线功能、接口要求和类型标识，这些成员将被继承或需要在从它们派生的类中实现。这些成员的范围，包括**Properties**和**Methods**，按照约定，公共成员用**+**表示，私有成员用**-**表示，受保护的成员用**#**表示，尽管如前所述，Python 并没有真正的受保护或私有成员。不过，这些至少提供了成员的预期范围的一些指示。

# 在 hms_sys 中实现基本的业务对象

在开发过程的这一阶段，我们只是不知道所有业务对象类的确切功能是否将在即将构建的两个应用程序和服务中发挥作用。数据所有权规则——确定用户可以在对象内创建、更新或删除哪些数据——尚未详细说明，因此还不能做出这些决定。然而，仅基于这些对象的目的，我们已经有足够的信息来开始定义它们代表的数据以及这些数据点周围应该存在的约束。

我们可能已经有足够的信息来知道某些对象类型需要存在某些功能，例如，**Artisan**对象需要能够添加和删除相关的**Product**对象，即使我们还不知道这将如何运作，或者是否有关于这些对象的数据所有权规则。我们还可以对哪些类需要是抽象的做出一些合理的猜测（因为它们的实际实现将在应用程序和服务之间变化）。

# Address

`Address`类表示一个物理位置——可以将某物邮寄或运送到的地方，或者可以在地图上找到的地方。无论对象在什么上下文中遇到，地址的属性都将是一致的——也就是说，地址是地址，无论它是与**Artisan**、**Customer**还是**Order**相关联的——并且在这一点上，可以放心地假设任何地址的整体都可以被其所属的对象更改，或者都不可以。在这一点上，除非有相反的信息，否则似乎不需要将地址作为后端数据结构中的单独项存储；尽管它们可能会有自己的有意义的独立存在，但没有理由假设它们会有。

考虑到这一点，至少目前为止，将地址作为抽象类并不感觉是必要的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/7887406d-de5a-4e06-9e15-6d0b50c80f46.png)

地址是一个愚蠢的数据对象，至少目前为止；它由一个数据结构组成，但没有方法或功能。类本身的属性相当简单，并且围绕它们有一些规则：

+   `street_address`是位置的街道地址。它应该是一个单行字符串值，是必需的（不能是空的），并且可能不允许除空格之外的任何空白字符。`street_address`的一个示例值可能是`1234 Main Street`。

+   `building_address`是地址的可选第二行，用于指示关于实际位置的街道地址的更多细节。示例可能包括公寓号、套房或办公室位置或编号等。如果在任何给定的地址中存在，它应该是一个具有与`street_address`相同约束的字符串值，但同样，它是一个可选值。

+   `city`是一个必需的字符串值，同样限制为单行，并且与`street_address`具有相同的空白规则。

+   `region`是一个可选的字符串值，具有与`postal_code`和`country`相同的约束，至少目前是这样。

这最后三个属性很难在没有某种特定国家上下文的情况下制定规则。在某些国家，地址可能没有地区或邮政编码，而在其他国家，它们可能有完全不同的名称和数据要求，尽管这似乎不太可能。例如，考虑到在美国，地区和`postal_code`代表**州**和**邮政编码**（五个数字，带有一个可选的破折号和另外四个数字），而在加拿大，它们代表一个领土或省份和一个字母数字混合的邮政编码。对于一些要求，可能会有一个按国家划分的解决方案，在初步处理完属性定义之后将对此进行检查。

`Address`的初始实现非常简单；我们首先定义一个具有可用属性的类：

```py
class Address:
    """
Represents a physical mailing-address/location
"""
    ###################################
    # Class attributes/constants      #
    ###################################

# ... removed for brevity

    ###################################
    # Instance property definitions   #
    ###################################

    building_address = property(
        _get_building_address, _set_building_address, 
        _del_building_address, 
        'Gets, sets or deletes the building_address (str|None) '
        'of the instance'
    )
    city = property(
        _get_city, _set_city, _del_city, 
        'Gets, sets or deletes the city (str) of the instance'
    )
    country = property(
        _get_country, _set_country, _del_country, 
        'Gets, sets or deletes the country (str|None) of the '
        'instance'
    )
    region = property(
        _get_region, _set_region, _del_region, 
        'Gets, sets or deletes the region (str|None) of the '
        'instance'
    )
    postal_code = property(
        _get_postal_code, _set_postal_code, _del_postal_code, 
        'Gets, sets or deletes the postal_code (str|None) of '
        'the instance'
    )
    street_address = property(
        _get_street_address, _set_street_address, 
        _del_street_address, 
        'Gets, sets or deletes the street_address (str) of the '
        'instance'
    )
```

每个`property`调用都指定了必须实施的 getter、setter 和 deleter 方法。getter 方法都非常简单，每个方法都返回存储该属性实例数据的相关属性值：

```py
    ###################################
    # Property-getter methods         #
    ###################################

    def _get_building_address(self) -> (str,None):
        return self._building_address

    def _get_city(self) -> str:
        return self._city

    def _get_country(self) -> (str,None):
        return self._country

    def _get_region(self) -> (str,None):
        return self._region

    def _get_postal_code(self) -> (str,None):
        return self._postal_code

    def _get_street_address(self) -> str:
        return self._street_address
```

尽管必须实施一些逻辑以强制执行前面提到的类型和值规则，但设置方法也相对简单。到目前为止，地址的属性分为两类：

+   必填，非空，单行字符串（例如`street_address`）

+   可选（`None`）或非空，单行字符串值（`building_address`）

所需值的实现将都遵循相同的模式，以`street_address`为例：

```py
    def _set_street_address(self, value:str) -> None:
        # - Type-check: This is a required str value
        if type(value) != str:
            raise TypeError(
                '%s.street_address expects a single-line, '
                'non-empty str value, with no whitespace '
                'other than spaces, but was passed '
                '"%s" (%s)' % 
                (
                    self.__class__.__name__, value, 
                    type(value).__name__
                )
            )
        # - Value-check: no whitespace other than " "
        bad_chars = ('\n', '\r', '\t')
        is_valid = True
        for bad_char in bad_chars:
            if bad_char in value:
                is_valid = False
                break
        # - If it's empty or otherwise not valid, raise error
        if not value.strip() or not is_valid:
            raise ValueError(
                '%s.street_address expects a single-line, '
                'non-empty str value, with no whitespace '
                'other than spaces, but was passed '
                '"%s" (%s)' % 
                (
                    self.__class__.__name__, value, 
                    type(value).__name__
                )
            )
        # - Everything checks out, so set the attribute
        self._street_address = value
```

设置方法的过程，从头到尾，如下所示：

1.  确保提交的`value`是`str`类型，并且如果不是这种情况则引发`TypeError`

1.  创建一个禁止字符列表——换行符、回车符和制表符（`'\n'`、`'\r'`、`'\t'`）——不应该允许在值中出现

1.  假设该值有效，直到另有确定（`is_valid = True`）

1.  检查值中是否存在这些非法字符，并且如果存在，则标记该值为无效

1.  检查值是否只是空格（`value.strip()`）或是否找到了任何无效字符，如果是，则引发`ValueError`

1.  如果没有引发错误，则将属性的内部存储属性设置为现在经过验证的值（`self._street_address = value`）

相同的代码，将`street_address`更改为`city`，处理了城市属性的 setter 实现。这个属性 setter 的过程/流程将反复出现，在这个迭代和后续的迭代中。从现在开始使用时，它将被称为标准必需文本行属性 setter。

可选属性使用非常相似的结构，但首先检查（并允许）`None`值，因为将它们的值设置为`None`在技术上是有效的/允许的。`building_address`属性 setter 就是这一过程的一个例子：

```py
    def _set_building_address(self, value:(str,None)) -> None:
        if value != None:
            # - Type-check: If the value isn't None, then it has to 
            #   be a non-empty, single-line string without tabs
            if type(value) != str:
                raise TypeError(
                    '%s.building_address expects a single-line, '
                    'non-empty str value, with no whitespace '
                    'other than spaces or None, but was passed '
                    '"%s" (%s)' % 
                    (
                        self.__class__.__name__, value, 
                        type(value).__name__
                    )
                )
            # - Value-check: no whitespace other than " "
            bad_chars = ('\n', '\r', '\t')
            is_valid = True
            for bad_char in bad_chars:
                if bad_char in value:
                    is_valid = False
                    break
            # - If it's empty or otherwise not valid, raise error
            if not value.strip() or not is_valid:
                raise ValueError(
                    '%s.building_address expects a single-line, '
                    'non-empty str value, with no whitespace '
                    'other than spaces or None, but was passed '
                    '"%s" (%s)' % 
                    (
                        self.__class__.__name__, value, 
                        type(value).__name__
                    )
                )
            # - If this point is reached without error, then the 
            #   string-value is valid, so we can just exit the if
        self._building_address = value
```

这个 setter 方法的过程，就像前面的标准必需文本行属性一样，将会经常出现，并且将被称为标准可选文本行属性 setter。

删除方法也将非常简单——如果删除了这些属性中的任何一个，都可以将其设置为`None`，以便它们仍然具有值（从而避免在其他地方引用时出现`AttributeError`的实例），但可以用于指示没有值的值：

```py
    def _del_building_address(self) -> None:
        self._building_address = None

    def _del_city(self) -> None:
        self._city = None

    def _del_country(self) -> None:
        self._country = None

    def _del_region(self) -> None:
        self._region = None

    def _del_postal_code(self) -> None:
        self._postal_code = None

    def _del_street_address(self) -> None:
        self._street_address = None
```

通过定义属性及其基础方法，使类可用的唯一剩下的就是定义其`__init__`方法，以便实际接受和存储相关属性的`Address`实例的创建。

很诱人只坚持简单的结构，接受并要求各种地址元素的顺序与它们通常使用的顺序相同，类似于这样：

```py
    def __init__(self, 
        street_address,                  # 1234 Main Street
        building_address,                # Apartment 3.14
        city, region, postal_code,       # Some Town, ST, 00000
        country                          # Country. Maybe.
        ):
```

同样有效的另一种方法是允许参数的默认值，这些默认值将转换为实例创建的可选属性：

```py
    def __init__(self, 
        street_address,                  # 1234 Main Street
        city,                            # Some Town
        building_address=None,           # Apartment 3.14
        region=None, postal_code=None,   # ST, 00000
        country=None                     # Country
        ):
```

从功能的角度来看，这两种方法都是完全有效的——可以使用任一种方法创建`Address`实例——但第一种方法可能更容易理解，而第二种方法则允许创建一个最小的实例，而无需每次都担心指定每个参数值。关于使用哪种参数结构应该涉及一些严肃的思考，包括以下因素：

+   谁将创建新的`Address`实例？

+   这些`Address`创建过程是什么样的？

+   何时何地需要新的`Address`实例？

+   它们将如何被创建？也就是说，这个过程周围是否会有某种 UI，并且是否会有任何一致性？

“谁”这个问题有一个非常简单的答案，而且大多数情况下也能回答其他问题：几乎任何用户都可能需要能够创建新地址。中央办公室工作人员在设置新的**Artisan**账户时可能会需要。**Artisans**偶尔可能需要，如果他们需要更改他们的地址。**顾客**虽然只是间接地，在他们下第一个订单时会需要，而且可能需要为运输单独创建地址，而不是使用他们自己的默认/账单地址。甚至**Artisan**网关服务可能需要创建`Address`实例，作为处理数据来回移动的过程的一部分。

在大多数情况下，会涉及某种 UI：**顾客**和**订单**相关项目的网店表单，以及**Artisan**和中央办公室应用程序中的任何 GUI。在地址创建过程中有一个 UI，将参数从 UI 传递给`__init__`的责任只对开发人员来说才重要或关注。因此，这些问题虽然能够揭示功能需求是什么，但在选择两种参数形式之间并没有太大帮助。

也就是说，`__init__`可以以一种方式定义，而为`Address`创建另一种结构的方法，例如`standard_address`：

```py
    @classmethod
    def standard_address(cls, 
            street_address:(str,), building_address:(str,None), 
            city:(str,), region:(str,None), postal_code:(str,None), 
            country:(str,None)
        ):
        return cls(
            street_address, city, building_address, 
            region, postal_code, country
        )
```

这样就允许`__init__`使用结构，利用各种默认参数值：

```py
def __init__(self, 
    street_address:(str,), city:(str,), 
    building_address:(str,None)=None, region:(str,None)=None, 
    postal_code:(str,None)=None, country:(str,None)=None
    ):
    """
Object initialization.

self .............. (Address instance, required) The instance to 
                    execute against
street_address .... (str, required) The base street-address of the 
                    location the instance represents
city .............. (str, required) The city portion of the street-
                    address that the instance represents
building_address .. (str, optional, defaults to None) The second 
                    line of the street address the instance represents, 
                    if applicable
region ............ (str, optional, defaults to None) The region 
                    (state, territory, etc.) portion of the street-
                    address that the instance represents
postal_code ....... (str, optional, defaults to None) The postal-code 
                    portion of the street-address that the instance 
                    represents
country ........... (str, optional, defaults to None) The country 
                    portion of the street-address that the instance 
                    represents
"""
    # - Set default instance property-values using _del_... methods
    self._del_building_address()
    self._del_city()
    self._del_country()
    self._del_postal_code()
    self._del_region()
    self._del_street_address()
    # - Set instance property-values from arguments using 
    #   _set_... methods
    self._set_street_address(street_address)
    self._set_city(city)
    if building_address:
        self._set_building_address(building_address)
    if region:
        self._set_region(region)
    if postal_code:
        self._set_postal_code(postal_code)
    if country:
        self._set_country(country)
```

这使得`Address`在功能上是完整的，至少对于本次迭代中关于它的故事来说是这样。

在任何类正在开发过程中，开发人员可能会出现关于他们设想的用例的问题，或者在考虑类的某些方面时会出现问题。在`Address`被完善时出现的一些例子如下：

+   如果在实例中删除了非默认属性值，会发生什么？如果删除了必需的值，那么实例将不再是完整的，从技术上讲是无效的结果——甚至可能会发生这样的删除吗？

+   有一个 Python 模块，`pycountry`，它收集 ISO 衍生的国家和地区信息。是否希望尝试利用这些数据，以确保国家/地区的组合是现实的？

+   `Address`最终是否需要任何输出能力？例如标签文本？或者可能需要生成 CSV 文件中的一行？

这些问题可能值得保存在某个地方，即使它们从未变得相关。如果没有某种项目系统存储库来保存这些问题，或者开发团队中没有一些流程来保存它们，以免它们丢失，它们总是可以被添加到代码本身中，作为某种注释，也许像这样：

```py
# TODO: Consider whether Address needs some sort of #validation 
#       mechanism that can leverage pycountry to assure #that 
#       county/region combinations are kosher.
#       pycountry.countries—collection of countries
#       pycountry.subdivisions—collection of regions by #country
# TODO: Maybe we need some sort of export-mechanism? Or a 
#       label-ready output?
# TODO: Consider what can/should happen if a non-default #property-
#       value is deleted in an instance. If a required #value is 
#       deleted, the instance is no longer well-formed...
class Address:
    """
#Represents a physical mailing-address/location
"""
```

# BaseArtisan

`Artisan`类代表参与手工制品市场的工匠——一个通过中央办公室的网店销售产品的人。知道几乎每个用户与最终`Artisan`类的交互都几乎肯定会有不同的功能规则，因此在`hms_core`代码库中创建一个抽象类来定义其他包中任何具体`Artisan`的共同功能和要求是有意义的。我们将把这个类命名为`BaseArtisan`。

就像我们刚刚完成的`Address`类一样，`BaseArtisan`的设计和实现始于一个类图：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/0a445950-577b-44bb-9176-75d7383ad17d.png)

抽象类通常具有指示它们是抽象的命名约定。在这种情况下，Base 的前缀就是这个指示符，并且将在开发过程中用于其他抽象类。

`BaseArtisan`旨在为系统中任何部分的任何`Artisan`关联的所有属性提供一组通用的状态数据规则和功能。属性本身将是具体的实现。此外，`BaseArtisan`还旨在以`add_product`和`remove_product`方法的形式提供一些（最小的）功能要求。由于工匠和产品彼此相关，因此一个具体的`Artisan`对象需要能够添加和删除`Product`对象，但是关于这些过程的具体细节可能会在两个应用程序和使用该功能的服务之间有所不同，因此它们将是抽象的——需要在从`BaseArtisan`派生的任何类中被覆盖/实现。

该类图还包括了之前创建的`Address`类，两个类之间有一个菱形结束的连接器。该连接表示`Address`类被用作`BaseArtisan`的聚合属性——也就是说，`BaseArtisan`的地址属性是`Address`的一个实例。在地址属性本身中也有这种表示，地址属性的类型指定为`<Address>`。简单来说，一个`BaseArtisan`有一个`Address`。

也可以将`BaseArtisan`定义为从`Address`继承。该关系的类图几乎与上面相同，除了连接器，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/74358f19-2088-48eb-8097-1f0d77f8e0b8.png)

在这种关系中，`BaseArtisan`是一个`Address`——它将拥有`Address`的所有属性，以及可能在后续添加的任何方法成员。这两种关系都是完全合法的，但在继承上使用聚合（或组合）方法而不是依赖继承有一些值得注意的优势，这些优势值得在移动到`BaseArtisan`的实现之前注意。

# OO 原则-组合优于继承

很可能最明显的优势之一是结构容易理解。一个“工匠”实例将有一个地址属性，该属性是另一个对象，该对象有其自己的相关属性。在“工匠”级别上，只有一个重要的地址，这可能看起来并不重要。然而，其他对象，比如“顾客”和“订单”，可能有多个关联的地址（例如，账单地址和送货地址），甚至可能有几个：“顾客”可能有几个需要保留和可用的送货地址。

随着系统的对象库变得越来越庞大和复杂，使用纯继承的设计方法将不可避免地导致大量的类树，其中许多类可能只是提供功能，目的仅仅是为了被继承。基于组合的设计将减少这种复杂性，在更大更复杂的库中可能会显著减少，因为功能将封装在单个类中，这些类的实例本身就成为属性。

然而，这种组合也有一些潜在的缺点：深度嵌套的对象，属性的属性的属性*无休止地*，可能会导致长链的数据结构。例如，在`hms_sys`的上下文中，如果一个“订单”有一个“顾客”，顾客又有一个“送货地址”，那么从“订单”中找到该地址的“邮政编码”看起来会像是`order.customer.shipping_address.postal_code`。这并不是一个非常深或复杂的路径来获取涉及的数据，因为属性名称很容易理解，所以理解整个路径并不困难。与此同时，很容易想象这种嵌套会失控，或者依赖于不那么容易理解的名称。

还有可能（也许很可能）需要一个类来提供一些组合属性类方法的本地实现，这增加了父对象类的复杂性。举个例子，假设刚才提到的`shipping_address`的地址类有一个方法，检查各种运输 API 并返回一个从最低到最高成本排序的列表—称之为`find_best_shipping`。如果有一个要求`order`对象能够使用该功能，那可能最终会在订单类级别定义一个`find_best_shipping`方法，调用地址级别的方法并返回相关数据。

然而，这些都不是重大的缺点。只要在确保设计逻辑和易于理解，成员名称有意义的情况下进行一些纪律性的练习，它们可能不会比单调更糟。

从更纯粹的面向对象的角度来看，一个更重要的问题是菱形问题。考虑以下代码：

```py
class Root:
    def method(self, arg, *args, **kwargs):
        print('Root.method(%s, %s, %s)' % (arg, str(args), kwargs))

class Left(Root):
    def method(self, arg, *args, **kwargs):
        print('Left.method(%s, %s, %s)' % (arg, str(args), kwargs))

class Right(Root):
    def method(self, arg, *args, **kwargs):
        print('Right.method(%s, %s, %s)' % (arg, str(args), kwargs))

class Bottom(Left, Right):
    pass

b = Bottom()
```

这些类形成了一个菱形，因此有了菱形问题的名称：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/5d7e7c53-3fd0-4fde-a5d8-0ba31e420401.png)

以下代码执行时会发生什么：

```py
b.method('arg', 'args1', 'args2', keyword='value')
```

哪个方法会被调用？除非语言本身定义了如何解决歧义，否则唯一可以肯定的是`Root`的方法不会被调用，因为`Left`和`Right`类都对其进行了重写。

Python 通过使用类定义中指定的继承顺序作为**方法解析顺序**（**MRO**）来解决这种性质的歧义。在这种情况下，因为`Bottom`被定义为从`Left`和`Right`继承—`class Bottom(Left, Right)`—这个顺序将被用来确定实际执行哪个可用的`method`：

```py
# Outputs "Left.method(arg, ('args1', 'args2'), {'keyword': 'value'})"
```

尽管似乎不太可能任何可安装的`hms_sys`组件会达到继承问题成为重大关注的程度，但并不能保证永远不会发生。鉴于这一点，以及从基于继承到基于组合的重构工作可能会非常痛苦并且容易引入破坏性变化，即使在这一点上，基于组合的方法，即使具有一些固有的缺点，也感觉像是更好的设计。

# 实现 BaseArtisan 的属性

为了将**工匠**表示为一个人（可能还有公司名称），具有位置和产品，`BaseArtisan`提供了六个属性成员：

+   `contact_name`是**工匠**的联系人姓名。它应该是一个标准的必需文本行属性，如前所定义。

+   `contact_email`是`contact_name`中提到的人的电子邮件地址。它应该是一个格式良好的电子邮件地址，并且是必需的。

+   `company_name`是一个标准的可选文本行属性（可选，因为并非所有**工匠**都有公司名称）。

+   `address`将是必需的，并且将是`Address`的一个实例。

+   `website`是**工匠**的可选网站地址。如果存在，它将需要是一个格式良好的 URL。

+   `products`将是`BaseProduct`对象的集合，方式与`address`是一个`Address`实例的方式相似。一些关于产品的实现细节将被推迟，直到`BaseProduct`被完全定义。

与之前一样，流程从创建类开始，并定义其实现的属性：

```py
class BaseArtisan(metaclass=abc.ABCMeta):
    """
Provides baseline functionality, interface requirements, and 
type-identity for objects that can represent an Artisan in 
the context of the HMS system.
"""
```

将`metaclass=abc.ABCMeta`包含在内定义了`BaseArtisan`作为抽象基类，使用`abc`模块的`ABCMeta`功能：

```py
    ###################################
    # Instance property definitions   #
    ###################################

    address = property(
        _get_address, _set_address, _del_address, 
        'Gets, sets or deletes the physical address (Address) '
        'associated with the Artisan that the instance represents'
    )
    company_name = property(
        _get_company_name, _set_company_name, _del_company_name, 
        'Gets, sets or deletes the company name (str) associated '
        'with the Artisan that the instance represents'
    )
    contact_email = property(
        _get_contact_email, _set_contact_email, _del_contact_email, 
        'Gets, sets or deletes the email address (str) of the '
        'named contact associated with the Artisan that the '
        'instance represents'
    )
    contact_name = property(
        _get_contact_name, _set_contact_name, _del_contact_name, 
        'Gets, sets or deletes the name of the contact (str) '
        'associated with the Artisan that the instance represents'
    )
    products = property(
        _get_products, None, None, 
        'Gets the collection of products (BaseProduct) associated '
        'with the Artisan that the instance represents'
    )
    website = property(
        _get_website, _set_website, _del_website, 
        'Gets, sets or deletes the URL of the website (str) '
        'associated with the Artisan that the instance represents'
    )
```

由于`company_name`和`contact_name`是标准的可选和必需的文本行实现，就像在创建`Address`类时描述的那样，它们的实现将遵循在那里建立的模式，并且不会被详细检查。它们的过程与`Address.building_address`和`Address.street_address`的过程相同，唯一变化的是 getter、setter 和 deleter 方法的名称以及存储属性的状态数据属性。

同样，与除产品之外的所有属性相关的`_get_`和`_del_`方法将遵循已经建立的相同基本模式：

+   Getter 方法将简单地返回存储在相应状态存储属性中的值

+   删除方法将将相应状态存储属性的值设置为`None`

例如，`address`、`company_name`和`contact_email`的 getter 和 deleter 方法的实现可以与先前显示的完全相同的过程，即使`address`不是一个简单的值属性，`contact_email`还没有被实现：

```py
    def _get_address(self) -> (Address,):
        return self._address

    def _del_address(self) -> None:
        self._address = None

    def _get_company_name(self) -> (str,None):
        return self._company_name

    def _del_company_name(self) -> None:
        self._company_name = None

    def _get_contact_email(self) -> (str,None):
        return self._contact_email

    def _del_contact_email(self) -> None:
        self._contact_email = None
```

这可能感觉像大量样板文件，复制和粘贴的代码，但这是能够执行由 setter 方法处理的类型和值检查的成本。setter 方法本身是保持所需的高度数据类型和完整性的魔法发生的地方。

`address`属性的 setter 可能会出乎意料地简单，因为实际上只需要强制执行传递给它的任何值必须是`Address`类的实例。没有值检查，因为任何成功创建的`Address`实例都将在初始化过程中执行自己的类型和值检查：

```py
    def _set_address(self, value:Address) -> None:
        if not isinstance(value, Address):
            raise TypeError(
                '%s.address expects an Address object or an object '
                'derived from Address, but was passed "%s" (%s) '
                'instead, which is not.' %
                (value, type(value).__name__)
            )
        self._address = value
```

`contact_email`的 setter 可以工作得像在`Address._set_street_address`中定义的标准必需文本行 setter 过程一样。毕竟，它有一些相同的数据规则——它是一个必需值，不能是空的，而且由于它是一个电子邮件地址，它不能是多行或包含制表符。然而，由于它是一个电子邮件地址，它也不能包含空格，并且有其他字符限制是所有电子邮件地址共有的，这些限制在原始结构中没有考虑到。由于该属性的要求包括它是一个格式良好的电子邮件地址，可能有其他更好的方法来验证传递给 setter 的值。

理想情况下，应用程序将希望确保电子邮件地址既格式良好又有效。然而，确实只有一种方法可以实现其中任何一种，而且这超出了`hms_sys`的范围，即使尝试实现也是有意义的：发送确认电子邮件，并且在收到确认响应之前/除非不存储该值。

有许多方法可以让我们完成大部分验证格式良好的电子邮件地址的工作。可能最好的起点是使用正则表达式与该值匹配，或者删除所有格式良好的电子邮件地址，并且在执行替换后不允许设置该值，除非剩下的内容为空。使用正则表达式可能不会保证该值格式良好，但它将捕获许多无效值。将其与`email.utils`模块中找到的一些标准 Python 功能结合起来，至少可以使代码达到一个测试点，以查找失败的格式良好的地址，并允许修改检查过程。

首先，我们需要从`email.utils`中导入`parseaddr`函数和`re`模块中的一些项目，以便创建我们将用于测试的正则表达式对象。这些导入应该发生在模块的顶部：

```py
#######################################
# Standard library imports needed     #
#######################################

import abc # This was already present
import re

from email.utils import parseaddr
```

接下来，我们将创建一个模块级常量正则表达式对象，用于检查电子邮件地址值：

```py
EMAIL_CHECK = re.compile(
    r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'
)
```

这将匹配以一个或多个字符*A*到*Z*（大写或小写）、任何数字 0-9 或下划线、句点、加号或破折号开头的整个字符串，然后是`@`，然后是大多数域名。这种结构是在互联网上进行快速搜索时找到的，可能不完整，但看起来应该适用于大多数电子邮件地址。现在，setter 方法的所有实现需要做的就是检查该值是否为字符串，从字符串中解析出可识别的地址，检查解析后的值，如果一切正常，设置数据存储属性的值：

```py
    def _set_contact_email(self, value:str) -> None:
        # - Type-check: This is a required str value
        if type(value) != str:
            raise TypeError(
                '%s.contact_email expects a str value that is a '
                'well-formed email address, but was passed '
                '"%s" (%s)' % 
                (
                    self.__class__.__name__, value, 
                    type(value).__name__
                )
            )
        # - Since we know it's a string, we can start by parsing value 
        #   with email.utils.parseaddr, and using the second item of 
        #   that result to check for well-formed-ness
        check_value = parseaddr(value)[1]
        # - If value is not empty, then there was *something* that was
        #   recognized as being an email address
        valid = (check_value != '')
        if valid:
            # - Try removing an entire well-formed email address, as 
            #   defined by EMAIL_CHECK, from the value. If it works, 
            #   there will either be a remnant or not. If there is 
            #   a remnant, it's considered badly-formed.
            remnant = EMAIL_CHECK.sub('', check_value)
            if remnant != '' or not value:
                valid = False
        if not check_value or not valid:
            raise TypeError(
                '%s.contact_email expects a str value that is a '
                'well-formed email address, but was passed '
                '"%s" (%s)' % 
                (
                    self.__class__.__name__, value, 
                    type(value).__name__
                )
            )
        self._contact_email = value
```

类似的方法应该是网站 setter 方法的一个很好的起点，使用以下作为正则表达式进行测试：

```py
URL_CHECK = re.compile(
    r'(^https?://[A-Za-z0-9][-_A-Za-z0-9]*\.[A-Za-z0-9][-_A-Za-z0-9\.]*$)'
)
```

它以与`Address._set_building_address`中建立的相同可选值检查开始，但使用`URL_CHECK`正则表达式对象来检查传入的值，方式与`_set_contact_email`相同：

```py
    def _set_website(self, value:(str,None)) -> None:
        # - Type-check: This is an optional required str value
        if value != None:
            if type(value) != str:
                raise TypeError(
                    '%s.website expects a str value that is a '
                    'well-formed URL, but was passed '
                    '"%s" (%s)' % 
                    (
                        self.__class__.__name__, value, 
                        type(value).__name__
                    )
                )
            remnant = URL_CHECK.sub('', value)
            if remnant != '' or not value:
                raise TypeError(
                    '%s.website expects a str value that is a '
                    'well-formed URL, but was passed '
                    '"%s" (%s)' % 
                    (
                        self.__class__.__name__, value, 
                        type(value).__name__
                    )
                )
        self._website = value
```

现在只剩下一个属性要实现：`products`。`products`属性具有一些方面，一开始可能不明显，但对应该如何实现它可能有潜在的重要影响。首先，它是其他对象的集合——无论是列表、字典还是其他什么——但无论如何，它都不是像`address`那样的单个对象。此外，它被定义为只读属性：

```py
    products = property(
        _get_products, None, None, 
        'Gets the collection of products (BaseProduct) associated '
        'with the Artisan that the instance represents'
    )
```

`property`定义中只提供了 getter 方法。这是有意为之，但需要一些解释。

由于产品旨在处理产品对象的集合，因此`products`属性本身不能更改为其他内容非常重要。例如，如果产品是可设置的，就有可能执行以下操作：

```py
# Given artisan = Artisan(...whatever initialization…)
artisan.products = 'Not a product collection anymore!'
```

当然，可以实施类型和值检查代码来防止这种赋值方式，尽管属性本身没有与之关联的 setter 方法，但我们几乎肯定会在以后需要一个，而且它应该实施该类型和值检查。然而，它的使用可能仅限于在创建工匠实例期间填充实例的产品。

另一个潜在的问题是，可能会以容易出错和难以调节的方式更改集合的成员资格。例如，使用相同的`artisan`实例，并假设产品的底层数据存储是列表，没有任何阻止代码执行以下任何操作：

```py
artisan.products.append('This is not a product!')
artisan.products[0] = 'This is also not a product!'
```

同样，允许任意删除工匠的产品（`del artisan.products`）可能不是一个好主意。

因此，至少，我们希望确保以下内容：

+   不允许或不能影响真实的底层数据的`products`成员资格

+   仍然允许访问（也许是操作）单个`products`成员的成员，也就是说，给定产品实例的列表，从中读取数据并向其写入数据不受其所在集合的限制

即使没有开发某种自定义集合类型，也有几种选择。由于`products`属性使用 getter 方法来获取和返回值，因此可以更改返回的数据，以便：

+   直接返回实际数据的副本，这样更改返回集合的成员资格不会影响原始集合

+   将数据以不同的集合类型返回副本；例如，如果真实数据存储在列表中，返回该列表的元组将提供与原始列表相同的可迭代序列功能，但不允许更改副本本身的成员资格

Python 通过对象引用跟踪对象——也就是说，它通过与分配给对象的名称相关联的内存中的位置来关注对象实际存在的位置——因此，当从已经存在的对象列表创建对象的列表或元组时，新集合的成员与原始列表中存在的对象相同，例如：

```py
# - Create a class to demonstrate with
class Example:
    pass

# -  Create a list of instances of the class
example_list = [
    Example(), Example(), Example(), Example()
]

print('Items in the original list (at %s):' % hex(id(example_list)))
for item in example_list:
    print(item)

# Items in the original list (at 0x7f9cd9ed6a48):
# <__main__.Example object at 0x7f9cd9eed550>
# <__main__.Example object at 0x7f9cd9eed5c0>
# <__main__.Example object at 0x7f9cd9eed5f8>
# <__main__.Example object at 0x7f9cd9eed630>
```

创建原始列表的副本将创建一个新的独立集合，其中仍然包含相同的成员：

```py
new_list = list(example_list)
print('Items in the new list (at %s):' % hex(id(new_list)))
for item in new_list:
    print(item)

# Items in the new list (at 0x7f9cd89dca88):
# <__main__.Example object at 0x7f9cd9eed550>
# <__main__.Example object at 0x7f9cd9eed5c0>
# <__main__.Example object at 0x7f9cd9eed5f8>
# <__main__.Example object at 0x7f9cd9eed630>
```

创建元组也需要类似的方式：

```py
new_tuple = tuple(example_list)
print('Items in the new tuple (at %s):' % hex(id(new_tuple)))
for item in new_tuple:
    print(item)

# Items in the new tuple (at 0x7f9cd9edd4a8):
# <__main__.Example object at 0x7f9cd9eed550>
# <__main__.Example object at 0x7f9cd9eed5c0>
# <__main__.Example object at 0x7f9cd9eed5f8>
# <__main__.Example object at 0x7f9cd9eed630>
```

因此，返回从原始状态数据值创建的新列表或元组将处理防止对属性值进行的更改影响真正的基础数据。目前，元组返回选项似乎是更好的选择，因为它更加严格，这种情况下`_get_products`将被实现如下：

```py
def _get_products(self) -> (tuple,):
  return tuple(self._products)
```

删除方法`_del_products`不能使用`None`作为默认值，因为现在已经有了 getter。它将必须更改为其他内容，因为尝试返回一个`None`默认值的`tuple`会引发错误。目前，删除的值将更改为一个空列表：

```py
def _del_products(self) -> None:
  self._products = []
```

最后，这是设置方法，`_set_products`：

```py
    def _set_products(self, value:(list, tuple)) -> None:
        # - Check first that the value is an iterable - list or 
        #   tuple, it doesn't really matter which, just so long 
        #   as it's a sequence-type collection of some kind.
        if type(value) not in (list, tuple):
            raise TypeError(
                '%s.products expects a list or tuple of BaseProduct '
                'objects, but was passed a %s instead' % 
                (self.__class__.__name__, type(value).__name__)
            )
        # - Start with a new, empty list
        new_items = []
        # - Iterate over the items in value, check each one, and 
        #   append them if they're OK
        bad_items = []
        for item in value:
            # - We're going to assume that all products will derive 
            #   from BaseProduct - that's why it's defined, after all
            if isinstance(item, BaseProduct):
                new_items.append(item)
            else:
                bad_items.append(item)
        # - If there are any bad items, then do NOT commit the 
        #   changes -- raise an error instead!
        if bad_items:
            raise TypeError(
                '%s.products expects a list or tuple of BaseProduct '
                'objects, but the value passed included %d items '
                'that are not of the right type: (%s)' % 
                (
                    self.__class__.__name__, len(bad_items), 
                    ', '.join([str(bi) for bi in bad_items])
                )
            )
        self._products = value
```

综合起来，这些变化相当大地限制了对产品属性的更改：

+   属性本身是只读的，不允许设置或删除值

+   从 getter 方法返回的值与实际存储在其状态数据中的值相同，但不同，并且虽然它仍然允许访问原始集合的成员，但不允许更改原始集合的成员资格

+   设置方法强制对整个集合进行类型检查，确保集合的成员只由适当的对象类型组成

尚未考虑的是对集合成员进行实际更改的过程——这种能力在方法成员中。

# 实现 BaseArtisan 的方法

`BaseArtisan`，按照当前的设计，应该提供两个抽象方法：

+   `add_product`，需要一个机制来添加`products`到实例的产品集合中，需要在派生的具体类中实现

+   `remove_product`，同样需要一个机制来从派生实例的`products`集合中删除项目

这些被指定为抽象方法，因为虽然在`hms_sys`的应用和服务可安装组件中，每个方法几乎肯定会涉及一些共同的功能，但在这些相同的组件中也几乎肯定会有显著的实现差异——例如，artisans 可能是唯一可以真正从他们的`products`集合中删除项目的用户。

通常，在大多数支持定义抽象方法的编程语言中，这些方法不需要提供任何实际的实现。事实上，定义方法为抽象方法可能会禁止任何实现。Python 并不强制这种限制在抽象方法上，但也不期望有任何实现。因此，我们的抽象方法不需要比这更复杂：

```py
 @abc.abstractmethod
 def add_product(self, product:BaseProduct):
    pass

 @abc.abstractmethod
 def remove_product(self, product:BaseProduct):
    pass
```

虽然我们允许在抽象方法中放入具体实现，但是在某些情况下，可以利用这一点，在一个地方提供基线功能。这两种方法，`add_product`和`remove_product`，属于这种情况：

+   添加产品总是需要进行类型检查，当出现无效类型时引发错误，并将新项目附加到实例的集合中

+   从实例的产品集合中删除指定产品总是涉及到删除产品

考虑到这些因素，将这些常见流程放入抽象方法中实际上是有益的，就好像它们是具体实现一样。这些流程可以从派生类实例中调用，无论在执行基线本身之前还是之后，都可以加入或不加入额外的逻辑。考虑在`BaseArtisan`中实现`add_product`的基本方法如下：

```py
    @abc.abstractmethod
    def add_product(self, product:BaseProduct):
        """
Adds a product to the instance's collection of products.

Returns the product added.

self ....... (BaseArtisan instance, required) The instance to 
             execute against
product ...  (BaseProduct, required) The product to add to the 
             instance's collection of products

Raises TypeError if the product specified is not a BaseProduct-
  derived instance

May be implemented in derived classes by simply calling
    return BaseArtisan.add_product(self, product)
"""
        # - Make sure the product passed in is a BaseProduct
        if not isinstance(product, BaseProduct):
            raise TypeError(
                '%s.add_product expects an instance of '
                'BaseProduct to be passed in its product '
                'argument, but "%s" (%s) was passed instead' % 
                (
                    self.__class__.__name__, value, 
                    type(value).__name__
                )
            )
        # - Append it to the internal _products list
        self._products.append(product)
        # - Return it
        return product
```

一个派生类——例如，位于总部应用程序中的`Artisan`类——将需要实现`add_product`，但可以按照以下方式实现：

```py
    def add_product(self, product:BaseProduct):
        # - Add any additional checking or processing that might 
        #   need to happen BEFORE adding the product here

        # - Call the parent add_product to perform the actual 
        #   addition
        result = BaseArtisan.add_product(self, product)

        # - Add any additional checking or processing that might 
        #   need to happen AFTER adding the product here

        # - Return the product
        return result
```

不过，这种方法存在一个权衡：派生类可以实现一个全新的`add_product`流程，跳过现成的验证/业务规则。另一种方法是定义一个抽象验证方法（也许是`_check_products`），它处理验证过程，并由`add_product`的具体实现直接调用。

`remove_product`方法可以类似地定义，并且可以在派生类实例中以类似的方式实现：

```py
    @abc.abstractmethod
    def remove_product(self, product:BaseProduct):
        """
Removes a product from the instance's collection of products.

Returns the product removed.

self ....... (BaseArtisan instance, required) The instance to 
             execute against
product ...  (BaseProduct, required) The product to remove from 
             the instance's collection of products

Raises TypeError if the product specified is not a BaseProduct-
  derived instance
Raises ValueError if the product specified is not a member of the 
  instance's products collection

May be implemented in derived classes by simply calling
    return BaseArtisan.remove_product(self, product)
"""
        # - Make sure the product passed in is a BaseProduct.
        #   Technically this may not be necessary, since type 
        #   is enforced in add_product, but it does no harm to 
        #   re-check here...
        if not isinstance(product, BaseProduct):
            raise TypeError(
                '%s.add_product expects an instance of '
                'BaseProduct to be passed in its product '
                'argument, but "%s" (%s) was passed instead' % 
                (
                    self.__class__.__name__, value, 
                    type(value).__name__
                )
            )
        try:
            self._products.remove(product)
            return product
        except ValueError:
            raise ValueError(
                '%s.remove_product could not remove %s from its '
                'products collection because it was not a member '
                'of that collection' % 
                (self.__class__.__name__, product)
            )
```

可能还有其他方法适合添加到`BaseArtisan`中，但如果有的话，它们可能会在具体`Artisan`类的实现中出现。现在，我们可以在定义了`__init__`方法之后称`BaseArtisan`为完成：

```py
    def __init__(self, 
        contact_name:str, contact_email:str, 
        address:Address, company_name:str=None, 
        **products
        ):
        """
Object initialization.

self .............. (BaseArtisan instance, required) The instance to 
                    execute against
contact_name ...... (str, required) The name of the primary contact 
                    for the Artisan that the instance represents
contact_email ..... (str [email address], required) The email address 
                    of the primary contact for the Artisan that the 
                    instance represents
address ........... (Address, required) The mailing/shipping address 
                    for the Artisan that the instance represents
company_name ...... (str, optional, defaults to None) The company-
                    name for the Artisan that the instance represents
products .......... (BaseProduct collection) The products associated 
                    with the Artisan that the instance represents
"""
        # - Call parent initializers if needed
        # - Set default instance property-values using _del_... methods
        self._del_address()
        self._del_company_name()
        self._del_contact_email()
        self._del_contact_name()
        self._del_products()
        # - Set instance property-values from arguments using 
        #   _set_... methods
        self._set_contact_name(contact_name)
        self._set_contact_email(contact_email)
        self._set_address(address)
        if company_name:
            self._set_company_name(company_name)
        if products:
            self._set_products(products)
        # - Perform any other initialization needed
```

# 基础客户

定义客户数据结构的类非常简单，并且使用了已经在`Address`和`BaseArtisan`中建立的代码结构来定义其所有属性。就像`BaseArtisan`与具体`Artisan`实例的关系一样，预期`Customer`对象在其所能做的事情上会有很大的变化，也许在系统的不同组件之间允许的数据访问上也会有所不同。再次，我们将首先定义一个 ABC——`BaseCustomer`——而不是一个具体的`Customer`类：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/4d1ea61e-9206-4487-bb53-828c74428616.png)

`BaseCustomer`的属性包括：

+   `name`，一个标准的必填文本行。

+   `billing_address`和`shipping_address`，除了它们的名称之外，与`BaseArtisan`中定义的地址属性相同。`shipping_address`将是可选的，因为客户可能只有一个地址用于两者。

`BaseCustomer`的唯一值得一提的新方面是在初始化期间对`shipping_address`进行注释。`BaseCustomer.__init__`基本上会遵循之前类定义中展示的相同结构/方法：

```py
    def __init__(self, 
        name:str, billing_address:Address, 
        shipping_address(Address,None)=None
    ):
        """
Object initialization.

self .............. (BaseCustomer instance, required) The instance to 
                    execute against
name .............. (str, required) The name of the customer.
billing_address ... (Address, required) The billing address of the 
                    customer
shipping_address .. (Address, optional, defaults to None) The shipping 
                    address of the customer.
"""
        # - Call parent initializers if needed
        # - Set default instance property-values using _del_... methods
        self._del_billing_address()
        self._del_name()
        self._del_shipping_address()
        # - Set instance property-values from arguments using 
        #   _set_... methods
        self._set_name(name)
        self._set_billing_address(billing_address)
        if shipping_address:
            self._set_shipping_address(shipping_address)
        # - Perform any other initialization needed
```

`shipping_address`参数的注释`(Address,None)`是新的，有点新意。我们以前使用过内置类型作为注释类型，以及在可选参数规范中使用过内置的非`None`类型和`None`。`Address.__init__`在几个地方使用了这种表示法。尽管这段代码使用了我们定义的一个类，但它的工作方式是一样的：`Address`类也是一种类型，就像以前的例子中的`str`一样。它只是在这个项目中定义的一种类型。

# 基础订单

创建几乎任何愚蠢的数据对象类，甚至是大多数愚蠢的数据对象类，其过程非常相似，无论这些类代表什么，至少只要这些努力的整个范围内的数据结构规则保持不变。随着创建更多这样的面向数据的类，将需要更少的新方法来满足特定需求，直到最终将有一套简洁的方法来实现所需的各种类型和值约束的各种属性。

`BaseOrder`类，与`BaseProduct`一起显示，是这种效果的一个很好的例子，至少乍一看是这样的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/4f92b29d-afdd-4bcd-9188-fcd993c7ae6c.png)

`BaseOrder`属性列表非常简短，因为订单实际上代表的只是与一组产品的客户关系：

+   `customer` 是`BaseCustomer`的一个实例，而`BaseCustomer`又有该**顾客**的`billing_address`和`shipping_address`属性；除了属性值的类型将是`BaseCustomer`实例之外，可以合理地假设它将以与`BaseCustomer`的`Address`类型属性相同的方式运行

+   `products` 是`BaseProduct`实例的集合，可能可以完全像`BaseArtisan`的`products`属性一样运行——毕竟，它将做同样的事情，存储产品实例并防止对这些实例的改变——因此，它的初始实现将直接从`BaseArtisan`复制过来

简而言之，除了在**顾客**属性的情况下更改名称外，这两个属性已经有了已建立的实现模式，因此在`BaseOrder`中没有实质性的新内容可展示。

有时直接从一个类复制代码到另一个类是一个有争议的话题；即使一切都完美运行，根据定义，这是复制代码，这意味着如果以后出现问题，就需要维护多个副本的代码。

# BaseProduct

`BaseProduct` ABC 也有大量接近样板的属性代码，尽管其中只有三个属性符合到目前为止已经建立的实现模式：

+   `name` 是一个标准的必需文本行属性。

+   `summary` 是一个标准的必需文本行属性。

+   `description` 是一个可选的字符串值。

+   `dimensions` 是一个标准的可选文本行属性。

+   `shipping_weight` 是一个必需的数字值，可能仅用于确定运输成本，但也可能出现在网店的产品展示中。

+   `metadata` 是元数据键（字符串）和值（也是字符串）的字典。这是一个新的数据结构，所以我们很快就会详细研究它。

+   `available` 是一个必需的布尔值，允许工匠指示产品在 HMS 网店上可供销售，尽管可能对中央办公室工作人员可见。

+   `store_available` 也是一个必需的布尔值，表示 HMS 网店是否应该考虑**产品**可用。它打算由中央办公室工作人员控制，尽管可能对工匠可见。

`BaseProduct`目前只有两个关联的方法，用于管理与产品实例相关的元数据值：

+   `set_metadata` 将在实例上设置元数据键/值

+   `remove_metadata` 将从实例中删除元数据键和值

`name`、`summary`和`dimensions`属性作为标准的必需和可选文本行，将遵循这些模式。`description`几乎是一个可选文本行的实现；唯一需要改变的是删除空格字符检查，然后就可以使用了：

```py
# These lines aren't needed for description
# - Value-check: no whitespace other than " "
bad_chars = ('\n', '\r', '\t')
for bad_char in bad_chars:
    if bad_char in value:
       is_valid = False
       break
```

`shipping_weight`属性的实现在 setter 方法`_set_shipping_weight`中最为显著，但（希望）与项目中属性的典型方法结构相符，这是可以预期的：

```py
def _set_shipping_weight(self, value:(int,)):
  if type(value) != int:
    raise TypeError(
      '%s.shipping_weight expects a positive integer '
      'value, but was passed "%s" (%s)' % 
      (
         self.__class__.__name__, 
         value, type(value).__name__
       )
    )
   if value <= 0:
    raise ValueError(
      '%s.shipping_weight expects a positive integer '
       'value, but was passed "%s" (%s)' % 
       (
          self.__class__.__name__, 
          value, type(value).__name__
       )
    )
   self._shipping_weight = value
```

对于`available`属性的实现也可以这样说，尽管允许使用正式的布尔值（`True`和`False`）和整数值等价物（`1`和`0`）作为有效的 setter 值参数是有道理的。这在对象状态数据可能无法存储为真布尔值的情况下留有余地，尽管这是一个不太可能的情况，但也不是不可能的：

```py
def _set_available(self, value:(bool,int)):
   if value not in (True, False, 1, 0):
      raise ValueError(
        '%s.available expects either a boolean value '
         '(True|False) or a direct int-value equivalent '
         '(1|0), but was passed "%s" (%s)' % 
          (self.__class__.__name__, value, type(value).__name__)
          )
   if value:
      self._available = True
        else:
          self._available = False
```

这样就只剩下了`metadata`属性的实现。元数据可能最好被视为关于其他数据的数据——在这种情况下，是关于类基本上代表的产品的数据。在这种特殊情况下，`metadata`属性旨在提供高度灵活的数据，这些数据可能在一个产品（或产品类型）到另一个产品之间变化很大，同时仍然以相对简单的方式在更严格定义的类/对象结构中提供。这在 Hand Made Stuff 的需求背景下是很重要的，因为工匠通过他们的网店销售的产品几乎可以是任何东西：珠宝、木制品、金属家具、服装、珠宝等。虽然有一些描述可能适用于任何产品——例如它是由什么制成的，也许一些基本项目，比如颜色——但有一些描述使得几乎不可能在当前产品类结构中对整个可用范围的产品进行分类，而不是要求在当前产品类结构中有更多的数据结构，或者有很多产品类型，这些产品类型几乎肯定会在彼此之间有一个难以想象的复杂关系。

因此，初始实现和设计将围绕着维护每个对象的基于`dict`的元数据结构。如果以后出现更严格的要求（例如，要求木制品必须指定木材的类型），则可能需要进行相应的重构工作，但目前一个简单的`dict`看起来是合理的。

与`BaseArtisan`和`BaseOrder`的`products`属性一样，`BaseProduct`的`metadata`需要难以轻易或意外更改——它应该需要一些有意识的决定来进行更改。鉴于`metadata`结构预期提供用于对产品进行分类的数据，至少键将受到一定限制。元数据名称应该有意义并且相当简短。`metadata`值也应该是如此，尽管它们可能比相应的键受到的限制要少。

综合考虑所有这些项目，获取器和删除器方法与其他属性的等效方法并没有显着不同——通常只是名称更改和不同的删除默认值：

```py
    ###################################
    # Property-getter methods         #
    ###################################

    # ... 

    def _get_metadata(self) -> (dict,):
        return self._metadata

    # ... 

    ###################################
    # Property-deleter methods        #
    ###################################

    # ... 

    def _del_metadata(self) -> None:
        self._metadata = {}
```

设置方法通常是最常见的地方，其中存在显着的差异；在这种情况下，当调用时，期望是清除任何现有的元数据并用新的经过验证的键和值集合替换它。这将更改属性中的整个集合，而不仅仅是它的一些或全部成员。由于该类还将提供专用方法来允许添加新的`metadata`，或更改`metadata`中的现有项目，并且该方法将需要对键和值进行所需的任何验证，`_set_metadata`属性设置方法将使用同名的`set_metadata`方法来确保所有元数据都符合相同的标准。

第一步是确保传入的值是一个字典：

```py
    ###################################
    # Property-setter methods         #
    ###################################
# ... 

def _set_metadata(self, value:(dict,)):
 if type(value) != dict:
  raise TypeError(
   '%s.metadata expects a dictionary of metadata keys '
    '(strings) and values (also strings), but was passed '
         '"%s" (%s)' % 
    (self.__class__.__name__, value, type(value).__name__)
         )
```

我们将设置一个变量来跟踪遇到的任何无效值，并使用与在初始化期间清除当前元数据的相同机制`_del_metadata`。

```py
badvalues = []
self._del_metadata()
```

完成这些后，我们可以遍历值的键和值，对每一对调用`set_metadata`，直到它们都被记录，并捕获任何错误以提供更有用的错误消息时需要：

```py
if value: # Checking because value could be an empty dict: {}
  for name in value:
     try:
       # - Since set_metadata will do all the type- and 
       #   value-checking we need, we'll just call that 
       #   for each item handed off to us here...
           self.set_metadata(name, value[name])
     except Exception:
       # - If an error was raised,then we want to capture 
       #   the key/value pair that caused it...
             badvalues.append((name, value[name]))
```

如果检测到任何错误的值，那么我们将希望引发错误并记录它们。如果没有错误发生，那么属性已被重新填充：

```py
if badvalues:
   # - Oops... Something's not right...
    raise ValueError(
      '%s.metadata expects a dictionary of metadata keys '
      '(strings) and values, but was passed a dict with '
      'values that aren\'t allowed: %s' % 
         (self.__class__.__name__, str(badvalues))
       )
```

`set_metadata`方法看起来很像我们各种属性 setter 方法——元数据中的键和（目前）值都像标准的必需文本行属性一样操作——因此对每个属性执行的类型和数值检查看起来会非常熟悉：

```py
def set_metadata(self, key:(str,), value:(str,)):
   """
Sets the value of a specified metadata-key associated with the product 
that the instance represents.

self .............. (BaseProduct instance, required) The instance to 
                    execute against
key ............... (str, required) The metadata key to associate a 
                    value with
value ............. (str, required) The value to associate with the 
                    metadata key
"""
```

这里是对`key`参数值的类型和数值检查：

```py
if type(key) != str:
  raise TypeError(
    '%s.metadata expects a single-line, '
     'non-empty str key, with no whitespace '
     'other than spaces, but was passed "%s" (%s)' % 
     (
        self.__class__.__name__, key, 
        type(key).__name__
      )
    )
   # - Value-check of key: no whitespace other than " "
        bad_chars = ('\n', '\r', '\t')
        is_valid = True
        for bad_char in bad_chars:
            if bad_char in key:
                is_valid = False
                break
   # - If it's empty or otherwise not valid, raise error
    if not key.strip() or not is_valid:
       raise ValueError(
         '%s.metadata expects a single-line, '
         'non-empty str key, with no whitespace '
         'other than spaces, but was passed "%s" (%s)' % 
          (
            self.__class__.__name__, key, 
            type(key).__name__
          )
       )
```

这里是对`value`参数值的类型和数值检查：

```py
if type(value) != str:
  raise TypeError(
    '%s.metadata expects a single-line, '
    'non-empty str value, with no whitespace '
    'other than spaces, but was passed "%s" (%s)' % 
    (
       self.__class__.__name__, value, 
       type(value).__name__
    )
  )
  # - Value-check of value: no whitespace other than " "
     bad_chars = ('\n', '\r', '\t')
     is_valid = True
     for bad_char in bad_chars:
        if bad_char in value:
          is_valid = False
          break
  # - If it's empty or otherwise not valid, raise error
      if not value.strip() or not is_valid:
        raise ValueError(
          '%s.metadata expects a single-line, '
          'non-empty str value, with no whitespace '
          'other than spaces, but was passed "%s" (%s)' % 
            (
               self.__class__.__name__, value, 
               type(value).__name__
            )
         )
     self._metadata[key] = value
```

删除`metadata`需要的代码要短得多，也更简单，尽管它也假设如果试图删除不存在的元数据，则不需要引发错误。可能需要允许出现这样的错误，但目前的假设是不需要：

```py
def remove_metadata(self, key):
        """
Removes the specified metadata associated with the product that the 
instance represents, identified by the key

self .............. (BaseProduct instance, required) The instance to 
                    execute against
key ............... (str, required) The key that identifies the 
                    metadata value to remove
"""
        try:
            del self._metadata[key]
        except KeyError:
            pass
```

通过`BaseProduct`完成，`hms_core`类库的必需范围得到满足。单元测试仍需编写，并解决由此产生的任何问题。

# 处理重复的代码 - HasProducts

`BaseArtisan`和`BaseOrder`都有`products`属性，其行为方式相同，以至于这些属性的原始实现基本上涉及将代码从一个属性复制并粘贴到另一个属性中。在这种特定情况下可能并不是什么大问题（因为`hms_core`类库很小，成员很少，只有两个地方需要维护重复的代码），但在更大的库中，或者如果有很多重复的代码，问题可能会很快变得非常棘手。由于 Python 允许类从多个父类继承，我们可以利用这种能力来定义一个新的 ABC——`HasProducts`，将所有与产品属性相关的代码放在一个地方：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/e29b2099-a83d-4ea8-aaea-ea553f4752fc.png)

这种方法是面向对象原则的一种变体，通常被称为混入——一个包含功能具体实现以供其他类使用的类。

`HasProducts`的实现本质上只是`BaseArtisan`和`BaseOrder`的产品属性代码的集合或重新打包：

```py
class HasProducts(metaclass=abc.ABCMeta):
    """
Provides baseline functionality, interface requirements, and 
type-identity for objects that can have a common products 
property whose membership is stored and handled in the same 
way.
"""
```

getter、setter 和 deleter 方法：

```py
###################################
# Property-getter methods         #
###################################

def _get_products(self) -> (tuple,):
   return tuple(self._products)

###################################
# Property-setter methods         #
###################################

def _set_products(self, value:(list, tuple)) -> None:
# - Check first that the value is an iterable - list or 
#   tuple, it doesn't really matter which, just so long 
#   as it's a sequence-type collection of some kind.

 if type(value) not in (list, tuple):
   raise TypeError(
     '%s.products expects a list or tuple of BaseProduct '
     'objects, but was passed a %s instead' % 
     (self.__class__.__name__, type(value).__name__)
            )
  # - Start with a new, empty list
  new_items = []
  # - Iterate over the items in value, check each one, and 
  #   append them if they're OK
 bad_items = []
for item in value:
 # - We're going to assume that all products will derive 
 #   from BaseProduct - That's why it's defined, after all
      if isinstance(item, BaseProduct):
         new_items.append(item)
      else:
         bad_items.append(item)
 # - If there are any bad items, then do NOT commit the 
 #   changes -- raise an error instead!
     if bad_items:
      raise TypeError(
      '%s.products expects a list or tuple of BaseProduct'
      'objects, but the value passed included %d items '
      'that are not of the right type: (%s)' % 
      (
         self.__class__.__name__, len(bad_items), 
         ', '.join([str(bi) for bi in bad_items])
      )
   )
   self._products = value

###################################
# Property-deleter methods        #
###################################

  def _del_products(self) -> None:
    self._products = []
```

`products`属性定义：

```py
###################################
# Instance property definitions   #
###################################

products = property(
_get_products, None, None,
'Gets the products (BaseProduct) of the instance'
)
```

对象初始化：

```py
###################################
# Object initialization           #
###################################

def __init__(self, *products):
        """
Object initialization.

self .............. (HasProducts instance, required) The instance to 
                    execute against
products .......... (list or tuple of BaseProduct instances) The 
                    products that were ordered
"""
        # - Call parent initializers if needed
        # - Set default instance property-values using _del_... methods
        self._del_products()
        # - Set instance property-values from arguments using 
        #   _set_... methods
        if products:
            self._set_products(products)
        # - Perform any other initialization needed

###################################
# Abstract methods                #
###################################
```

用于添加和删除产品的抽象方法：

```py
    @abc.abstractmethod
    def add_product(self, product:BaseProduct) -> BaseProduct:
        """
Adds a product to the instance's collection of products.

Returns the product added.

self ....... (HasProducts instance, required) The instance to 
             execute against
product ...  (BaseProduct, required) The product to add to the 
             instance's collection of products

Raises TypeError if the product specified is not a BaseProduct-
  derived instance

May be implemented in derived classes by simply calling
    return HasProducts.add_product(self, product)
"""
        # - Make sure the product passed in is a BaseProduct
        if not isinstance(product, BaseProduct):
            raise TypeError(
                '%s.add_product expects an instance of '
                'BaseProduct to be passed in its product '
                'argument, but "%s" (%s) was passed instead' % 
                (
                    self.__class__.__name__, value, 
                    type(value).__name__
                )
            )
        # - Append it to the internal _products list
        self._products.append(product)
        # - Return it
        return product

    @abc.abstractmethod
    def remove_product(self, product:BaseProduct):
        """
Removes a product from the instance's collection of products.

Returns the product removed.

self ....... (HasProducts instance, required) The instance to 
             execute against
product ...  (BaseProduct, required) The product to remove from 
             the instance's collection of products

Raises TypeError if the product specified is not a BaseProduct-
  derived instance
Raises ValueError if the product specified is not a member of the 
  instance's products collection

May be implemented in derived classes by simply calling
    return HasProducts.remove_product(self, product)
"""
        # - Make sure the product passed in is a BaseProduct.
        #   Technically this may not be necessary, since type 
        #   is enforced in add_product, but it does no harm to 
        #   re-check here...
        if not isinstance(product, BaseProduct):
            raise TypeError(
                '%s.add_product expects an instance of '
                'BaseProduct to be passed in its product '
                'argument, but "%s" (%s) was passed instead' % 
                (
                    self.__class__.__name__, value, 
                    type(value).__name__
                )
            )
        try:
            self._products.remove(product)
            return product
        except ValueError:
            raise ValueError(
                '%s.remove_product could not remove %s from its '
                'products collection because it was not a member '
                'of that collection' % 
                (self.__class__.__name__, product)
            )
```

在`BaseArtisan`和`BaseOrder`中使用`HasProducts`并不困难，尽管它涉及重构以删除已经存在的代码，这些代码将覆盖`HasProducts`中的公共代码。首先要确保使用`HasProducts`的类继承自它：

```py
class BaseArtisan(HasProducts, metaclass=abc.ABCMeta):
    """
Provides baseline functionality, interface requirements, and 
type-identity for objects that can represent an Artisan in 
the context of the HMS system.
"""
```

派生类的`__init__`方法必须被修改为调用`HasProducts`的`__init__`，以确保它执行所有相关的初始化任务：

```py
def __init__(self, 
  contact_name:str, contact_email:str, 
  address:Address, company_name:str=None, 
  **products
  ):
    """
Object initialization.
"""
   # - Call parent initializers if needed
# This is all that's needed to perform the initialization defined 
# in HasProducts
        HasProducts.__init__(self, *products)
```

新类的默认值和实例值设置过程不再需要担心处理`products`属性的设置，因为这由`HasProducts.__init__`处理：

```py
        # - Set default instance property-values using _del_... methods
        self._del_address()
        self._del_company_name()
        self._del_contact_email()
        self._del_contact_name()
# This can be deleted, or just commented out.
#        self._del_products()
     # - Set instance property-values from arguments using 
        #   _set_... methods
        self._set_contact_name(contact_name)
        self._set_contact_email(contact_email)
        self._set_address(address)
        if company_name:
            self._set_company_name(company_name)
# This also can be deleted, or just commented out.
#        if products:
#            self._set_products(products)
```

最后，每个派生类中的`products`属性以及它们关联的 getter、setter 和 deleter 方法都可以被移除：

```py
# This also can be deleted, or just commented out.
#    products = property(
#         _get_products, None, None,
#         'Gets the products (BaseProduct) of the instance'
#    )
```

使用`HasProducts`在`BaseArtisan`和`BaseOrder`中实现后，`hms_core`包的完整结构和功能暂时完成——暂时是因为尚未进行单元测试。整个包的类图显示了所有的组成部分以及它们之间的关系：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/de3e0c91-0f1b-4f4c-8c47-d3dbf41517c3.png)

# 总结

总的来说，这些类提供的定义可以被描述为“愚蠢的数据对象”。它们提供的功能与特定数据结构的定义和规范直接相关，几乎没有其他功能。即使是`HasProducts`及其派生类也属于这一类，因为那里提供的功能严格关注于提供数据结构和控制如何操作该结构。随着从这些类派生出的其他类的创建，这些类将开始变得更智能，首先是对个体对象数据的持久化。

首先，需要编写这些类的单元测试，以确保它们已经经过测试，并且可以按需重新测试。由于这代表了编码目标的重大转变，并且将涉及对测试目标及其实现方式进行深入研究，因此这个第一次单元测试需要有自己的章节。
