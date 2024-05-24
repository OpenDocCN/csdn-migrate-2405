# PHP7 模块化编程（五）

> 原文：[`zh.annas-archive.org/md5/ff0acc039cf922de0886cd9283ec3d9f`](https://zh.annas-archive.org/md5/ff0acc039cf922de0886cd9283ec3d9f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：集成和分发模块

在前几章中，我们以模块化的方式构建了一个简单的网络商店应用程序。每个模块在处理各自的部分时都起着特殊的作用，这有助于整体应用程序。尽管应用程序本身是模块化编写的，但它被保存在一个 Git 单一版本控制存储库中。如果每个模块都在自己的存储库中提供，那将是一个更清晰的分离。这样，我们将能够将不同的模块开发作为完全不同的项目进行保留，同时仍然能够将它们一起使用。随着我们的前进，我们将看到如何通过 GIT 和 Composer 以两种不同的方式实现这一点。

在本章中，我们将涵盖以下工具和服务：

+   理解 Git

+   理解 GitHub

+   理解 Composer

+   理解 Packagist

# 理解 Git

最初由 Linus Torvalds 开始，Git 版本控制目前是最受欢迎的版本控制系统之一。与大型项目的整体速度和效率以及出色的分支系统一起，使其在开发人员中广受欢迎。

学习 Git 版本控制本身超出了本书的范围，建议阅读*Pro Git*书籍。

### 提示

由 Scott Chacon 和 Ben Straub 编写，由 Apress 出版的*Pro Git*书籍可以免费获取，网址为[`git-scm.com/book/en/v2`](https://git-scm.com/book/en/v2)。

Git 的一个很棒的功能是其子模块，这是我们在本章中感兴趣的部分。它们使我们能够将较大的模块化项目（例如我们的网络商店应用程序）切分为一系列较小的子模块，其中每个子模块都是一个独立的 Git 存储库。

# 理解 GitHub

Git 出现三年后，GitHub 出现了。GitHub 基本上是建立在 Git 版本控制系统之上的网络服务。它使开发人员能够轻松地将他们的代码发布到在线，其他人可以简单地克隆他们的存储库并使用他们的代码。在 GitHub 上创建帐户是免费的，可以通过按照官方主页上的说明来完成（[`github.com`](https://github.com)）。

目前，我们的应用程序结构如下图所示：

![理解 GitHub](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_12_02.jpg)

我们想要将其分成六个不同的 Git 存储库，如下所示：

+   核心

+   目录

+   客户

+   支付

+   销售

+   装运

`core`存储库应包含除`src/Foggyline`目录内容之外的所有内容。

假设我们在 GitHub 上创建了一个空的`core`存储库，并且我们的本地*all-in-one*应用程序当前保存在`shop`目录中，我们在计算机上初始化以下命令：

```php
**cp -R shop core-repository**
**rm -Rfcore-repository/.git/**
**rm -Rfcore-repository/src/Foggyline/***
**touch core-repository/src/Foggyline/.gitkeep**
**cd core-repository**
**git init**
**git remote add origin git@github.com:<user>/<core-repository>.git**
**git add --all**
**git commit -m "Initial commit of core application"**
**git push origin master**

```

此时，我们仅将我们的全能网络商店应用程序的核心部分推送到 GitHub 上的`core`存储库。`src/Foggyline/`目录中不包含任何模块。

现在，让我们回到 GitHub，并为五个模块（即`catalog`，`customer`，`payment`，`sales`和`shipment`）创建一个适当的空存储库。现在，我们可以为每个模块执行一组控制台命令，如下面的`CatalogBundle`示例所示：

```php
**cp -R shop/src/Foggyline/CatalogBundle catalog-repository**
**cd catalog-repository**
**git init**
**git remote add origin git@github.com:<user>/<catalog-repository>.git**
**git add --all**
**git commit -m "Initial commit of catalog module"**
**git push origin master**

```

一旦所有五个模块都被推送到存储库，我们最终可以将它们视为子模块，如下所示：

```php
**cd core-repository**
**git submodule add git@github.com:<user>/<catalog-repository>.git src/Foggyline/CatalogBundle**
**git submodule add git@github.com:<user>/<customer-repository>.git src/Foggyline/CustomerBundle**
**git submodule add git@github.com:<user>/<payment-repository>.git src/Foggyline/PaymentBundle**
**git submodule add git@github.com:<user>/<sales-repository>.git src/Foggyline/SalesBundle**
**git submodule add git@github.com:<user>/<shipment-repository>.git src/Foggyline/ShipmentBundle**

```

如果我们现在在`core`存储库目录中运行`ls-al`命令，我们应该能够看到一个`.gitmodules`文件，其中包含以下内容：

```php
**[submodule "src/Foggyline/CatalogBundle"]**
 **path = src/Foggyline/CatalogBundle**
**url = git@github.com:<user>/<catalog-repository>.git**

**[submodule "src/Foggyline/CustomerBundle"]**
 **path = src/Foggyline/CustomerBundle**
**url = git@github.com:<user>/<customer-repository>.git**

**[submodule "src/Foggyline/PaymentBundle"]**
 **path = src/Foggyline/PaymentBundle**
**url = git@github.com:<user>/<payment-repository>.git**

**[submodule "src/Foggyline/SalesBundle"]**
 **path = src/Foggyline/SalesBundle**
**url = git@github.com:<user>/<sales-repository>.git**

**[submodule "src/Foggyline/ShipmentBundle"]**
 **path = src/Foggyline/ShipmentBundle**
 **url = git@github.com:<user>/<shipment-repository>.git**

```

`.gitmodules`文件基本上包含了添加到我们核心项目（即核心应用程序）的所有子模块的列表。我们现在应该提交并推送这个文件到`core`存储库。假设`.gitmodules`文件被推送到`core`存储库，我们可以轻松地删除到目前为止创建的所有目录，并使用一个简单的命令初始化项目，如下所示：

```php
**git clone --recursive git@github.com:<user>/<core-repository>.git**

```

`git clone`命令的`--recursive`参数会根据`.gitmodules`文件自动初始化和更新存储库中的每个子模块。

# 理解 Composer

Composer 是 PHP 的一个依赖管理工具。默认情况下，它不会全局安装任何东西，而是基于每个项目进行安装。我们可以使用它来重新分发我们的项目，以定义它成功执行所需的库和包。使用 Composer 非常简单。它只需要在项目的根目录中创建一个`composer.json`文件，内容类似如下：

```php
{
"require": {
"twig/twig": "~1.0"
    }
}
```

如果我们在某个空目录中创建了前面的`composer.json`文件，并在该目录中执行`composer install`命令，Composer 将会读取`composer.json`文件并为我们的项目安装定义的依赖项。实际的`install`操作意味着从远程存储库下载所需的代码到我们的计算机上。在这样做的过程中，`install`命令会创建`composer.lock`文件，其中写入了已安装依赖项的确切版本列表。

我们还可以简单地执行`twig/twig:~1.0`命令，这是 Composer 所需的，它做的事情是一样的，但采用了不同的方法。它不需要我们编写`composer.json`文件，如果存在一个，它将对其进行更新。

了解 Composer 本身超出了本书的范围，建议的官方文档可在[`getcomposer.org/doc`](https://getcomposer.org/doc)找到。

Composer 允许打包和正式的依赖管理，使其成为将我们的一体化模块化应用程序切分为一系列 Composer 软件包的绝佳选择。这些软件包需要一个存储库。

# 了解 Packagist

在涉及 Composer 软件包时，主要的存储库是**Packagist**（[`packagist.org`](https://packagist.org)）。这是一个我们可以通过浏览器访问的网络服务，可以免费开设帐户，并开始向存储库提交我们的软件包。我们还可以使用它来搜索已经存在的软件包。

Packagist 通常用于免费开源软件包，尽管我们可以以相同的方式将**privateGitHub**和**BitBucket**存储库附加到其中，唯一的区别是私有存储库需要 SSH 密钥才能工作。

还有更方便的商业安装 Composer 包管理器的方法，比如**Toran Proxy**（[`toranproxy.com`](https://toranproxy.com)）。这允许更容易地托管私有软件包，提供更高的带宽以加快软件包安装速度，并提供商业支持。

到目前为止，我们将我们的应用程序切分为了六个不同的 Git 存储库，一个用于核心应用程序，其余五个分别用于每个模块（`catalog`、`customer`、`payment`、`sales`和`shipment`）。现在，让我们迈出最后一步，看看我们如何从 Git 子模块转移到 Composer 软件包。

假设我们在[`packagist.org`](https://packagist.org)上创建了一个帐户并成功登录，我们将首先点击**提交**按钮，这将使我们进入一个类似以下截图的屏幕：

![理解 Packagist](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_12_01.jpg)

在这里，我们需要提供我们现有的 Git、SVN 或 Mercurial（HG）存储库的链接。前面的示例提供了一个到 Git 存储库的链接（[`github.com/ajzele/B05460_CatalogBundle`](https://github.com/ajzele/B05460_CatalogBundle)）。在按下**检查**按钮之前，我们需要确保我们的存储库在其根目录中定义了一个`composer.json`文件，否则将会抛出类似以下截图中显示的错误。

![理解 Packagist](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_12_03.jpg)

然后，我们将为我们的`CatalogBundle`创建`composer.json`文件，内容如下：

```php
{
"name": "foggyline/catalogbundle",
"version" : "1.0.0",
"type": "library",
"description": "Just a test module for web shop application.",
"keywords": [
"catalog"
  ],
"homepage": "https://github.com/ajzele/B05460_CatalogBundle",
"license": "MIT",
"authors": [
    {
"name": "Branko Ajzele",
"email": "ajzele@gmail.com",
"homepage": "http://foggyline.net",
"role": "Developer"
    }
  ],
"minimum-stability": "dev",
"prefer-stable": true,
"autoload": {
"psr-0": {
"Foggyline\\CatalogBundle\\": ""
    }
  },
"target-dir": "Foggyline/CatalogBundle"
}
```

这里有很多属性，所有这些属性都在[`getcomposer.org/doc/04-schema.md`](https://getcomposer.org/doc/04-schema.md)页面上得到了充分的记录。

有了上述的`composer.json`文件，通过在控制台上运行`composer install`命令，将会在`vendor/foggyline/catalogbundle`目录下拉取代码，使得我们的 bundle 文件的完整路径为`vendor/foggyline/catalogbundle/Foggyline/CatalogBundle/FoggylineCatalogBundle.php`。

一旦我们将上述的`composer.json`文件添加到我们的 Git 存储库中，我们可以回到 Packagist，然后点击**Check**按钮，这将会出现一个类似下面截图的屏幕：

![理解 Packagist](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_12_04.jpg)

最后，当我们点击**Submit**按钮时，将会出现一个类似下面截图的屏幕：

![理解 Packagist](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_12_05.jpg)

我们的包现在已经添加到 Packagist 中，通过在控制台上运行以下命令，可以将其安装到项目中：

```php
**composer require foggyline/catalogbundle:dev-master**

```

同样，我们可以像下面的代码块中所示，向现有项目的`composer.json`文件中添加适当的条目：

```php
{
"require": {
"foggyline/catalogbundle": "dev-master"
    },
}
```

现在我们知道如何将应用程序分割成几个 Git 存储库和 Composer 包，我们需要对`src/Foggyline/`目录中剩余的模块做同样的操作，因为只有这些模块才会被注册为 Composer 包。

在`sales`模块开发过程中，我们注意到它依赖于其他几个模块，比如`catalog`和`customer`。我们可以使用`composer.json`文件的 require 属性来概述这种依赖关系。

一旦`src/Foggyline/`模块的所有 Git 存储库都更新了适当的`composer.json`定义，我们可以回到我们的核心应用程序存储库，并按照以下方式更新其`composer.json`文件中的`require`属性：

```php
{
"require": {
// ...
"foggyline/catalogbundle": "dev-master"
"foggyline/customerbundle": "dev-master"
"foggyline/paymentbundle": "dev-master"
"foggyline/salesbundle": "dev-master"
"foggyline/shipmentbundle": "dev-master"
        // ...
    },
}
```

在这一点上，使用子模块和包之间的区别可能并不那么明显。然而，与子模块不同，包允许版本控制。尽管我们的所有包都是从`dev-master`中拉取的，但如果有的话，我们也可以轻松地针对特定版本的包进行定位。

# 总结

在本章中，我们快速了解了 Git 和 Composer 以及如何通过 GitHub 和 Packagist 集成和分发我们的模块。在 Packagist 下发布包已经被证明是一个相当简单和容易的过程。所需的只是一个指向版本控制系统存储库的公共链接和项目根目录下的`composer.json`文件定义。

从头开始编写我们自己的应用程序并不一定意味着我们需要使用 Git 子模块或 Composer 包，就像本章所介绍的那样。Symfony 应用程序本身通过 bundle 结构化地模块化。当在 Symfony 项目上使用版本控制系统时，应该只保存我们的代码，这意味着所有的 Symfony 库和其他依赖项都应该在项目设置时通过 Composer 拉取。本章中展示的例子仅仅展示了如果我们想要编写可与他人共享的模块化组件，我们可以实现什么。例如，如果我们真的在开发一个健壮的`catalog`模块，其他有兴趣编写自己的网店的人可能会发现有兴趣要求并在他们的项目中使用它。

这本书从研究当前的 PHP 生态系统开始。然后我们涉及设计模式和原则，作为专业编程的基础。然后我们开始为我们的网店应用编写一个简短、更加直观的规范。最后，我们将我们的应用程序分成核心部分和几个其他较小的模块，然后根据规范进行编码。在这个过程中，我们熟悉了一些最常用的 Symfony 功能。我们编写的整体应用程序远非健壮。它只是一个最简单形式的网店，在功能方面还有很多不足之处。然而，应用的概念展示了在 PHP 中编写模块化应用程序可以是多么简单和快速。
