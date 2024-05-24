# Magento PHP 开发指南（四）

> 原文：[`zh.annas-archive.org/md5/f2e271327b273df27fc8bf4ef750d5c2`](https://zh.annas-archive.org/md5/f2e271327b273df27fc8bf4ef750d5c2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 A. 你好，Magento

以下示例将为您快速简单地介绍创建 Magento 扩展的世界。我们将创建一个简单的 Hello World 模块，当我们访问商店中的特定 URL 时，它将允许我们显示一个 Hello World！消息。

# 配置

在 Magento 中创建一个简单的扩展至少需要两个文件：`config.xml`和模块声明文件。让我们继续创建我们的每一个文件。

第一个文件用于向 Magento 声明模块；没有这个文件，Magento 将不会意识到任何扩展文件。

文件位置是`app/etc/modules/Mdg_Hello.xml`。请参考以下代码：

```php
<?xml version=”1.0”?>
<config>
    <modules>
        <Mdg_Hello>
            <active>true</active>
            <codePool>local</codePool>
        </Mdg_Hello>
    </modules>
</config>
```

第二个 XML 文件称为`config.xml`；它用于指定所有扩展配置，如路由、块、模型和助手类名称。对于我们的示例，我们只会使用控制器和路由。

让我们用以下代码创建配置文件。

文件位置是`app/code/local/Mdg/Hello/etc/config.xml`。请参考以下代码：

```php
<?xml version=”1.0”?>
<config>
    <modules>
        <Mdg_Hello>
            <version>0.1.0</version>
        </Mdg_Hello>
    </modules>
    <frontend>
        <routers>
            <mdg_hello>
                <use>standard</use>
                <args>
                    <module>Mdg_Hello</module>
                    <frontName>hello</frontName>
                </args>
            </mdg_hello>
        </routers>
    </frontend>
</config>
```

我们的扩展现在可以被 Magento 加载，并且您可以在 Magento 后端的**系统** | **配置** | **高级**中启用或禁用我们的扩展。

# 控制器

Magento 在其核心是一个**模型-视图-控制器**（**MVC**）框架。因此，为了使我们的新路由功能正常，我们必须创建一个新的控制器来响应这个特定的路由。要做到这一点，请按照以下步骤：

1.  导航到扩展根目录。

1.  创建一个名为`controllers`的新文件夹。

1.  在`controllers`文件夹内，创建一个名为`IndexController.php`的文件。

1.  复制以下代码（文件位置是`app/code/local/Mdg/Hello/controllers/IndexController.php`）：

```php
<?php
class Mdg_Hello_IndexController extends Mage_Core_Controller_Front_Action
{
     public function indexAction()
  {
     echo ‘Hello World this is the default action’;
     }
}
```

# 测试路由

现在我们已经创建了我们的路由器和控制器，我们可以通过打开`http://magento.localhost.com/hello/index/index`来测试它，我们应该会看到以下截图：

![测试路由](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_AppendixA_01.jpg)

默认情况下，Magento 将同时使用索引控制器和索引操作作为每个扩展的默认值。因此，如果我们转到`http://magento.localhost.com/hello/`，我们应该会看到相同的屏幕。

为了结束我们对 Magento 模块的介绍，让我们向我们的控制器添加一个新路由：

1.  导航到扩展根目录。

1.  打开`IndexController.php`。

1.  复制以下代码（文件位置是`app/code/local/Mdg/Hello/controllers/IndexController.php`）：

```php
<?php 
class Mdg_Hello_IndexController extends Mage_Core_Controller_Front_Action
{
     public function indexAction()
  {
     echo ‘Hello World this is the default action’;
     }

     public function developerAction()
     {
         echo ‘Hello Developer this is a custom controller action’;
     }
}
```

最后，让我们测试一下，并通过转到`http://magento.localhost.com/hello/index/developer`来加载新的操作路由，如下截图所示：

![测试路由](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_AppendixA_02.jpg)
