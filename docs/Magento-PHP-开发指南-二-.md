# Magento PHP 开发指南（二）

> 原文：[`zh.annas-archive.org/md5/f2e271327b273df27fc8bf4ef750d5c2`](https://zh.annas-archive.org/md5/f2e271327b273df27fc8bf4ef750d5c2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：前端开发

到目前为止，我们已经专注于 Magento 背后的理论、它的架构，并熟悉了日常 Magento 开发的常见和重要概念。

在本章中，我们将通过逐步构建一个 Magento 扩展来实际运用我们迄今所学到的技能和知识。我们将构建一个完全功能的礼品注册表扩展。

# 扩展 Magento

在跳入并开始构建我们的扩展之前，让我们定义一个示例情景和我们扩展的范围。这样我们将清楚地知道我们正在构建什么，更重要的是，我们不在构建什么。

## 情景

我们的情景很简单；我们想要扩展 Magento，允许客户创建礼品注册表并与朋友和家人分享。客户应该能够创建多个礼品注册表，并指定这些礼品注册表的接收者。

礼品注册表将保存以下信息：

+   事件类型

+   事件名称

+   事件日期

+   事件地点

+   产品列表

## 功能

看一下以下功能：

+   商店管理员可以定义多个事件类型（生日、婚礼和礼品注册表）

+   创建事件并为每个事件分配多个礼品注册表列表

+   客户可以从购物车、愿望清单或直接从产品页面将产品添加到他们的注册表中

+   客户可以拥有多个礼品注册表

+   人们可以通过电子邮件和/或直接链接与朋友和家人分享他们的注册表

+   朋友和家人可以从礼品注册表购买物品

## 进一步的改进

以下是可能被省略在这个示例扩展中的一些功能列表，因为它们的复杂性，或者在社交媒体的情况下，由于它们的 API 和社交媒体平台的数量是不断变化的，但它们仍然是对想要进一步扩展这个模块的读者来说一个很好的挑战：

+   社交媒体整合

+   注册表可以跟踪每个注册表项目的请求和完成数量

+   指定多个不同的注册表所有者

+   交付给注册表所有者地址

# 你好 Magento

在前几章中，我们了解了 Magento 的代码池（核心、社区、本地）。由于我们不打算在 Magento Connect 上分发我们的模块，我们将在本地目录下创建它。

所有 Magento 模块都保存在包或命名空间中；例如，所有核心 Magento 模块都保存在 Mage 命名空间下。为了本书的目的，我们将使用 Magento 开发者指南（MDG）。

模块的 Magento 命名约定是`Namespace_Modulename`。

我们的下一步将是创建模块结构和配置文件。我们需要在`app/code/local/`下创建一个命名空间目录。命名空间可以是任何你喜欢的东西。被接受的惯例是使用公司的名称或作者的名称作为命名空间。因此，我们的第一步将是创建目录`app/code/local/Mdg/`。这个目录不仅将保存我们的礼品注册表模块，还将保存我们开发的任何未来模块。

在我们的命名空间目录下，我们还需要创建一个新的目录，其中包含我们自定义扩展的所有代码。

让我们继续创建一个`Giftregistry`目录。一旦完成，让我们创建剩下的目录结构。

### 注意

请注意，由于 Magento 使用工厂方法，对驼峰命名法有些敏感。一般来说，在我们的模块/控制器/操作名称中避免使用驼峰命名法是个好主意。有关 Magento 命名约定的更多信息，请参阅本书的附录。

文件位置是`/app/code/local/Mdg/Giftregistry/`。

```php
Block/
Controller/
controllers/
Helper/
etc/
Model/
sql/
```

到目前为止，我们已经了解到，Magento 使用`.xml`文件作为其配置的中心部分。为了让 Magento 识别并激活模块，我们需要在`app/etc/modules/`下创建一个文件，遵循`Namespace_Modulename.xml`约定。让我们创建我们的文件。

文件位置是`app/etc/modules/Mdg_Giftregistry.xml`。

```php
<?xml version="1.0"?>
<config>
    <modules>
        <Mdg_Giftregistry>
            <active>true</active>
            <codePool>local</codePool>
        </Mdg_Giftregistry >
    </modules>
</config>
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以直接通过电子邮件接收文件。

创建此文件或对我们的模块配置文件进行任何更改后，我们需要刷新 Magento 配置缓存：

1.  导航到 Magento 后端。

1.  打开**系统** | **缓存管理**。

1.  点击**刷新 Magento**。

由于我们正在开发扩展，并且将频繁更改配置和扩展代码，最好禁用缓存。按照以下步骤进行：

1.  导航到 Magento 后端。

1.  打开**系统** | **缓存管理**。

1.  选择所有**缓存类型**复选框。

1.  从**操作**下拉列表中选择**禁用**。

1.  点击**提交**按钮。![你好，Magento](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_04_01_revised.jpg)

清除缓存后，我们可以通过进入**系统** | **高级**来确认我们的扩展是否已激活。

![你好，Magento](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060_04_02.jpg)

现在 Magento 知道我们的模块了，但我们还没有告诉 Magento 我们的模块应该做什么；为此，我们需要设置模块配置。

# XML 模块配置

模块配置涉及两个主要文件：`config.xml`和`system.xml`。除了这些模块配置，这些也存储在：

+   `api.xml`

+   `adminhtml.xml`

+   `cache.xml`

+   `widget.xml`

+   `wsdl.xml`

+   `wsi.xml`

+   `convert.xml`

在本章中，我们将只关注`config.xml`文件。让我们创建我们的基本文件，并按照以下步骤分解每个节点：

1.  首先，在我们的模块`etc/directory`下创建`config.xml`文件。

1.  现在，将以下代码复制到`config.xml`文件中（文件位置为`app/code/local/Mdg/Giftregistry/etc/config.xml`）：

```php
<?xml version="1.0"?>
<config>
    <modules>
        <Mdg_Giftregistry>
            <version>0.1.0</version>
        </Mdg_Giftregistry>
    </modules>
    <global>
        <models>
            <mdg_giftregistry>
                <class>Mdg_Giftregistry_Model</class>
            </mdg_giftregistry>
        </models>
        <blocks>
            <mdg_giftregistry>
                <class>Mdg_Giftregistry_Block</class>
            </mdg_giftregistry>
        </blocks>
        <helpers>
            <mdg_giftregistry>
                <class>Mdg_Giftregistry_Helper</class>
            </mdg_giftregistry>
        </helpers>
        <resources>
            <mdg_giftregistry_setup>
                <setup>
                    <module>Mdg_Giftregistry</module>
                </setup>
            </mdg_giftregistry_setup>
        </resources>
    </global>
</config>
```

所有模块配置都包含在`<config>`节点内。在这个节点内，我们有`<global>`和`<modules>`节点。

`<modules>`节点只用于指定当前模块版本，稍后用于决定运行哪些安装和升级文件。

有三个主要的配置节点通常用于指定配置范围：

+   `<global>`

+   `<adminhtml>`

+   `<frontend>`

现在，我们将在`<global>`范围内工作。这将使任何配置对 Magento 前端和后端都可用。在`<global>`节点下，我们有以下节点：

+   `<models>`

+   `<blocks>`

+   `<helpers>`

+   `<resources>`

正如我们所看到的，每个节点都遵循相同的配置模式：

```php
<context>
   <factory_alias>
       <class>NameSpace_ModuleName_ClassType</class>
   </factory_alias>
</context>
```

Magento 类工厂使用的每个节点都实例化我们的自定义对象。`<factory_alias>`节点是我们扩展配置的关键部分。`<factory_alias>`节点由工厂方法使用，例如`Mage::getModel()`或`Mage::getHelper()`。

注意，我们没有定义每个特定的 Model、Block 或 Helper，只是 Magento 工厂可以找到它们的路径。Magento 的命名约定允许我们在这些文件夹下有任何文件夹结构，Magento 将聪明地加载适当的类名。

### 注意

在 Magento 中，类名和目录结构是一样的。

例如，我们可以在`app/code/local/Mdg/Giftregistry/Models/Folder1/Folder2/Folder3`下创建一个新的模型类，用于从这个类实例化对象的工厂名称将是：

```php
Mage::getModel('mdg_giftregistry/folder1_folder2_folder3_classname');
```

让我们创建我们的第一个模型，或者更具体地说，一个帮助类。帮助类用于包含用于执行常见任务的实用方法，并且可以在不同的类之间共享。

让我们继续创建一个空的`helper`类；我们将在本章后面添加帮助逻辑。

文件位置为`app/code/loca/Mdg/Giftregistry/Helper/Data.php`。参考以下代码：

```php
<?php
class Mdg_Giftregistry_Helper_Data extends Mage_Core_Helper_Abstract {

}
?>
```

我们命名帮助类为`Data`可能看起来有点奇怪，但这实际上是 Magento 的标准，每个模块都有一个名为`Data`的默认`helper`类。`helper`类的另一个有趣之处是，我们可以只传递`<factory_alias>`节点而不需要特定类名到`helper`工厂方法，这将默认为`Data`帮助类。

因此，如果我们想要实例化我们的默认`helper`类，我们只需要执行以下操作：

```php
Mage::helper('mdg_registry');
```

# 模型和保存数据

在直接创建我们的模型之前，我们需要清楚地定义我们将要构建的模型类型和数量。因此，让我们回顾一下我们的示例场景。对于我们的礼品注册，似乎我们将需要两种不同的模型：

+   **注册模型**：此模型用于存储礼品注册信息，例如礼品注册类型、地址和接收者信息

+   **注册项目**：此模型用于存储每个礼品注册项目的信息（请求的数量，购买的数量，`product_id`）

虽然这种方法是正确的，但它并不满足我们示例场景的所有要求。通过将所有注册信息存储到单个表中，我们无法添加更多的注册类型而不修改代码。

因此，在这种情况下，我们将希望将我们的数据分解成多个表：

+   **注册实体**：此表用于存储礼品注册和事件信息

+   **注册类型**：通过将礼品注册类型存储到单独的表中，我们可以添加或删除事件类型

+   **注册项目**：此表用于存储每个礼品注册项目的信息（请求的数量，购买的数量，`product_id`）

现在我们已经定义了我们的数据结构，我们可以开始构建相应的模型，以便访问和操作我们的数据。

## 创建模型

让我们开始创建礼品注册类型模型，用于管理注册类型（婚礼、生日、宝宝洗澡等）。要做到这一点，请按照以下步骤：

1.  转到我们模块目录中的`Model`文件夹。

1.  创建一个名为`Type.php`的新文件，并将以下内容复制到文件中（文件位置为`app/code/local/Mdg/Giftregistry/Model/Type.php`）：

```php
<?php
class Mdg_Giftregistry_Model_Type extends Mage_Core_Model_Abstract
{
    public function __construct()
    {
        $this->_init('mdg_giftregistry/type');
        parent::_construct();
    }
}
```

我们还需要创建一个资源类；每个 Magento 数据模型都有自己的资源类。还需要澄清的是，只有直接处理数据的模型，无论是简单数据模型还是 EAV 模型，都需要一个`resource`类。要做到这一点，请按照以下步骤：

1.  转到我们模块目录中的`Model`文件夹。

1.  在`Model`下创建一个名为`Mysql4`的新文件夹。

1.  创建一个名为`Type.php`的新文件，并将以下内容复制到文件中（文件位置为`app/code/local/Mdg/Giftregistry/Model/Mysql4/Type.php`）：

```php
<?php
class Mdg_Giftregistry_Model_Mysql4_Type extends Mage_Core_Model_Mysql4_Abstract
{
    public function _construct()
    {
        $this->_init('mdg_giftregistry/type', 'type_id');
    }
}
```

最后，我们还需要一个`collection`类来检索所有可用的事件类型：

1.  转到我们模块目录中的`Model`文件夹。

1.  创建一个名为`Type.php`的新文件，并将以下内容复制到文件中（文件位置为`app/code/local/Mdg/Giftregistry/Model/Mysql4/Type/Collection.php`）：

```php
<?php
class Mdg_Giftregistry_Model_Mysql4_Type_Collection extends Mage_Core_Model_Mysql4_Collection_Abstract
{
    public function _construct()
    {
        $this->_init('mdg_giftregistry/type');
        parent::_construct();
    }
}
```

通过创建一个处理礼品注册项目的模型来做同样的事情。此模型将保存注册项目的所有相关产品信息。要做到这一点，请按照以下步骤：

1.  转到我们模块目录中的`Model`文件夹。

1.  创建一个名为`Item.php`的新文件，并将以下内容复制到文件中（文件位置为`app/code/local/Mdg/Giftregistry/Model/Item.php`）：

```php
<?php
class Mdg_Giftregistry_Model_Item extends Mage_Core_Model_Abstract
{
    public function __construct()
    {
        $this->_init('mdg_giftregistry/item');
        parent::_construct();
    }
}
```

让我们继续创建资源类：

1.  导航到我们模块目录中的`Model`文件夹。

1.  打开`Mysql4`文件夹

1.  创建一个名为`Item.php`的新文件，并将以下内容复制到文件中（文件位置为`app/code/local/Mdg/Giftregistry/Model/Mysql4/Item.php`）：

```php
<?php
class Mdg_Giftregistry_Model_Mysql4_Item extends Mage_Core_Model_Mysql4_Abstract
{
    public function _construct()
    {
        $this->_init('mdg_giftregistry/item', 'item_id');
    }
}
```

最后，让我们创建相应的`collection`类：

1.  导航到我们模块目录中的`Model`文件夹。

1.  创建一个名为`Collection.php`的新文件，并将以下内容复制到文件中（文件位置为`app/code/local/Mdg/Giftregistry/Model/Mysql4/Item/Collection.php`）：

```php
<?php
class Mdg_Giftregistry_Model_Mysql4_Item_Collection extends Mage_Core_Model_Mysql4_Collection_Abstract
{
    public function _construct()
    {
        $this->_init('mdg_giftregistry/item');
        parent::_construct();
    }
}
```

我们的下一步将是创建我们的注册表实体；这是我们注册表的核心，也是将所有内容联系在一起的模型。要做到这一点，请按照以下步骤进行：

1.  导航到我们模块目录中的`Model`文件夹。

1.  创建一个名为`Entity.php`的新文件，并将以下内容复制到文件中（文件位置为`app/code/local/Mdg/Giftregistry/Model/Entity.php`）：

```php
<?php
class Mdg_Giftregistry_Model_Entity extends Mage_Core_Model_Abstract
{
    public function __construct()
    {
        $this->_init('mdg_giftregistry/entity');
        parent::_construct();
    }
}
```

让我们继续创建`resource`类：

1.  导航到我们模块目录中的`Model`文件夹。

1.  打开`Mysql4`文件夹。

1.  创建一个名为`Entity.php`的新文件，并将以下内容复制到文件中（文件位置为`app/code/local/Mdg/Giftregistry/Model/Mysql4/Entity.php`）：

```php
<?php
class Mdg_Giftregistry_Model_Mysql4_Entity extends Mage_Core_Model_Mysql4_Abstract
{
    public function _construct()
    {
        $this->_init('mdg_giftregistry/entity', 'entity_id');
    }
}
```

最后，让我们创建相应的`collection`类：

1.  导航到我们模块目录中的`Model`文件夹。

1.  创建一个名为`Collection.php`的新文件，并将以下内容复制到文件中（文件位置为`app/code/local/Mdg/Giftregistry/Model/Mysql4/Entity/Collection.php`）：

```php
<?php
class Mdg_Giftregistry_Model_Mysql4_Entity_Collection extends Mage_Core_Model_Mysql4_Collection_Abstract
{
    public function _construct()
    {
        $this->_init('mdg_giftregistry/entity');
        parent::_construct();
    }
}
```

到目前为止，我们除了盲目地复制代码并将模型类添加到我们的模块中之外，还没有做任何事情。让我们使用**交互式 Magento 控制台**（**IMC**）测试我们新创建的模型。

让我们启动 IMC，并通过在 Magento 安装的根目录中运行以下命令来尝试新模型：

```php
**$ php shell/imc.php**

```

以下代码假定您正在运行带有示例数据的 Magento 测试安装，如果您正在使用 Vagrant 框安装，您已经拥有所有预加载的数据：

1.  我们将从加载客户端模型开始：

```php
**magento > $customer = Mage::getModel('customer/customer')->load(1);**

```

1.  接下来，我们需要实例化一个新的注册表对象：

```php
**magento > $registry = Mage::getModel('mdg_giftregistry/entity');**

```

1.  所有 Magento 模型中的一个方便的函数是“getData（）”函数，它返回所有对象属性的数组。让我们在 a，注册表和客户对象上运行此函数并比较输出：

```php
**magento > print_r($customer->getData());**
**magento > print_r($registry->getData());**

```

1.  正如我们注意到的，客户端为我们的 John Doe 示例记录设置了所有数据，而注册表对象返回完全空的`$regiarray`。通过运行以下代码来更改这一点：

```php
**magento > $registry->setCustomerId($customer->getId());**
**magento > $registry->setTypeId(1);**
**magento > $registry->setWebsiteId(1);**
**magento > $registry->setEventDate('2012-12-12');**
**magento > $registry->setEventCountry('CA');**
**magento > $registry->setEventLocation('Toronto');**

```

1.  现在让我们尝试再次打印注册表数据：

```php
**magento > print_r($registry->getData());**

```

1.  最后，为了使我们的更改永久生效，我们需要调用模型的`save`函数：

```php
**magento > $registry->save();**

```

哎呀！在保存产品时出现了问题；我们在控制台中得到了以下错误：

```php
Fatal error: Call to a member function beginTransaction() on a non-object in …/app/code/core/Mage/Core/Model/Abstract.php on line 313
```

发生了什么？被调用的`save（）`函数是父类`Mage_Core_Model_Mysql4_Abstract`的一部分，它反过来调用抽象类`save（）`函数，但我们缺少`config.xml`文件的一个关键部分。

为了让 Magento 正确识别要使用的资源类，我们需要为每个实体指定资源模型类和匹配的表。让我们按照以下步骤更新我们的配置文件：

1.  导航到扩展`etc/`文件夹。

1.  打开`config.xml`。

1.  使用以下代码更新`<model>`节点（文件位置为`app/code/local/Mdg/Giftregistry/Model/Entity.php`）：

```php
…
<models>
    <mdg_giftregistry>
        <class>Mdg_Giftregistry_Model</class>
        <resourceModel>mdg_giftregistry_mysql4</resourceModel>
    </mdg_giftregistry>
    <mdg_giftregistry_mysql4>
        <class>Mdg_Giftregistry_Model_Mysql4</class>
        <entities>
            <entity>
                <table>mdg_giftregistry_entity</table>
            </entity>
            <item>
                <table>mdg_giftregistry_item</table>
            </item>
            <type>
                <table>mdg_giftregistry_type</table>
            </type>
        </entities>
    </mdg_giftregistry_mysql4>
</models>
…
```

现在，在我们实际将产品保存到数据库之前，我们必须首先创建我们的数据库表；接下来，我们将学习如何使用设置资源来创建我们的表结构并设置我们的默认数据。

## 设置资源

现在我们已经创建了我们的模型代码，我们需要创建设置资源以便能够保存它们。设置资源将负责创建相应的数据库表。现在，我们可以直接使用纯 SQL 或工具如 PHPMyAdmin 来创建所有表，但这不是标准做法，通常情况下，我们不应直接修改 Magento 数据库。

为了实现这一点，我们将执行以下操作：

+   在我们的配置文件上定义一个设置资源

+   创建一个资源类

+   创建一个安装脚本

+   创建一个数据脚本

+   创建一个升级脚本

### 定义一个设置资源

当我们首次定义配置文件时，我们定义了一个`<resources>`节点：

文件位置为`app/code/local/Mdg/Giftregistry/etc/config.xml`。参考以下代码片段：

```php
…
<resources>
    <mdg_giftregistry_setup>
        <setup>
            <module>Mdg_Giftregistry</module>
        </setup>
    </mdg_giftregistry_setup>
</resources>
…
```

首先要注意的是，`<mdg_giftregistry_setup>`节点用作我们设置资源的唯一标识符；标准命名约定是`<modulename_setup>`，虽然不是必需的，但强烈建议遵循此命名约定。

我们还需要对`<setup>`节点进行更改，添加一个额外的 class 节点，并读取和写入连接：

文件位置为`app/code/local/Mdg/Giftregistry/etc/config.xml`。

```php
…
<resources>
    <mdg_giftregistry_setup>
        <setup>
            <module>Mdg_Giftregistry</module>
            <class>Mdg_Giftregistry_Model_Resource_Setup</class>
        </setup>
        <connection>
            <use>core_setup</use>
        </connection>
    </mdg_giftregistry_setup>
    <mdg_giftregistry_write>
        <connection>
            <use>core_write</use>
        </connection>
    </mdg_giftregistry_write>
    <mdg_giftregistry_read>
        <connection>
            <use>core_read</use>
        </connection>
    </mdg_giftregistry_read>
</resources>
…
```

对于基本的设置脚本，不需要创建此设置资源，可以使用`Mage_Core_Model_Resource_Setup`，但通过创建自己的设置类，我们可以提前规划并为未来的改进提供更大的灵活性。接下来，我们将在文件位置下创建设置资源类，否则将会出现 Magento 找不到设置资源类的错误。

在文件位置`app/code/local/Mdg/Giftregistry/Model/Resource/Setup.php`下创建设置资源类。参考以下代码片段：

```php
<?php
class Mdg_Giftregistry_Model_Resource_Setup extends Mage_Core_Model_Resource_Setup
{

}
```

目前，我们不需要对设置资源类做其他操作。

### 创建安装脚本

我们的下一步将是创建一个安装脚本。此脚本包含创建表的所有 SQL 代码，并在初始化模块时运行。首先，让我们再次快速查看我们的`config.xml`文件。如果我们记得，我们在`<global>`节点之前定义的第一个节点是`<modules>`节点。

文件位置为`app/code/local/Mdg/Giftregistry/etc/config.xml`。参考以下代码片段：

```php
<modules>
  <Mdg_Giftregistry>
     <version>0.1.0</version>
   </Mdg_Giftregistry>
</modules>
```

正如我们之前提到的，此节点在所有 Magento 模块上都是必需的，并用于识别我们模块的当前安装版本。Magento 使用此版本号来确定是否以及要运行哪些安装和升级脚本。

### 注意

关于命名约定：自 Magento 1.6 以来，安装脚本的命名约定已更改。最初使用了`Mysql4-install-x.x.x.php`的命名约定，目前已被弃用但仍受支持。

自 Magento 1.6 以来，安装脚本的命名约定已更改，现在开发人员可以使用三种不同的脚本类型：

+   **安装**：当模块首次安装且在`core_resource`表中不存在记录时使用此脚本

+   **升级**：如果`core_resource`表中的版本低于`config.xml`文件中的版本，则使用此脚本

+   **数据**：此脚本将在匹配版本的安装/升级脚本之后运行，并用于向表中填充所需数据

### 注意

数据脚本是在 Magento 1.6 中引入的，并存储在直接位于我们模块根目录下的 data/目录中。它们遵循与安装和升级脚本略有不同的约定，通过添加前缀。

让我们继续在我们的安装脚本下创建我们的注册表实体表。

文件位置为`app/code/local/Mdg/Giftregistry/sql/mdg_giftregistry_setup/install-0.1.0.php`。参考以下代码：

```php
<?php

$installer = $this;
$installer->startSetup();
// Create the mdg_giftregistry/registry table
$tableName = $installer->getTable('mdg_giftregistry/entity');
// Check if the table already exists
if ($installer->getConnection()->isTableExists($tableName) != true) {
    $table = $installer->getConnection()
        ->newTable($tableName)
        ->addColumn('entity_id', Varien_Db_Ddl_Table::TYPE_INTEGER, null,
            array(
                'identity' => true,
                'unsigned' => true,
                'nullable' => false,
                'primary' => true,
            ),
            'Entity Id'
        )
        ->addColumn('customer_id', Varien_Db_Ddl_Table::TYPE_INTEGER, null,
            array(
                'unsigned' => true,
                'nullable' => false,
                'default' => '0',
            ),
            'Customer Id'
        )
        ->addColumn('type_id', Varien_Db_Ddl_Table::TYPE_SMALLINT, null,
            array(
                'unsigned' => true,
                'nullable' => false,
                'default' => '0',
            ),
            'Type Id'
        )
        ->addColumn('website_id', Varien_Db_Ddl_Table::TYPE_SMALLINT, null,
            array(
                'unsigned' => true,
                'nullable' => false,
                'default' => '0',
            ),
            'Website Id'
        )
        ->addColumn('event_name', Varien_Db_Ddl_Table::TYPE_TEXT, 255,
            array(),
            'Event Name'
        )
        ->addColumn('event_date', Varien_Db_Ddl_Table::TYPE_DATE, null,
            array(),
            'Event Date'
        )
        ->addColumn('event_country', Varien_Db_Ddl_Table::TYPE_TEXT, 3,
            array(),
            'Event Country'
        )
        ->addColumn('event_location', Varien_Db_Ddl_Table::TYPE_TEXT, 255,
            array(),
            'Event Location'
        )
        ->addColumn('created_at', Varien_Db_Ddl_Table::TYPE_TIMESTAMP, null,
            array(
                'nullable' => false,
            ),
            'Created At')
        ->addIndex($installer->getIdxName('mdg_giftregistry/entity', array('customer_id')),
            array('customer_id'))
        ->addIndex($installer->getIdxName('mdg_giftregistry/entity', array('website_id')),
            array('website_id'))
        ->addIndex($installer->getIdxName('mdg_giftregistry/entity', array('type_id')),
            array('type_id'))
        ->addForeignKey(
            $installer->getFkName(
                'mdg_giftregistry/entity',
                'customer_id',
                'customer/entity',
                'entity_id'
            ),
            'customer_id', $installer->getTable('customer/entity'), 'entity_id',
            Varien_Db_Ddl_Table::ACTION_CASCADE, Varien_Db_Ddl_Table::ACTION_CASCADE)
        ->addForeignKey(
            $installer->getFkName(
                'mdg_giftregistry/entity',
                'website_id',
                'core/website',
                'website_id'
            ),
            'website_id', $installer->getTable('core/website'), 'website_id',
            Varien_Db_Ddl_Table::ACTION_CASCADE, Varien_Db_Ddl_Table::ACTION_CASCADE)
        ->addForeignKey(
            $installer->getFkName(
                'mdg_giftregistry/entity',
                'type_id',
                'mdg_giftregistry/type',
                'type_id'
            ),
            'type_id', $installer->getTable('mdg_giftregistry/type'), 'type_id',
            Varien_Db_Ddl_Table::ACTION_CASCADE, Varien_Db_Ddl_Table::ACTION_CASCADE);

    $installer->getConnection()->createTable($table);
}
$installer->endSetup();
```

### 注意

请注意，由于空间限制，我们没有添加完整的安装脚本；您仍然需要为项目和类型表添加安装程序代码。完整的安装文件和代码文件可以直接从[`github.com/amacgregor/mdg_giftreg`](https://github.com/amacgregor/mdg_giftreg)下载。

现在这可能看起来像是很多代码，但它只是创建了一个表的输出，为了理解它，让我们分解一下，看看这段代码到底在做什么。

首先要注意的是，即使我们正在创建和设置数据库表，我们并没有编写任何 SQL 代码。Magento ORM 提供了一个带有数据库的适配器。所有安装、升级和数据脚本都继承自`Mage_Core_Model_Resource_Setup`。让我们分解一下我们安装脚本上使用的每个函数。

脚本的前三行实例化了`resource_setup`模型和连接。脚本的其余部分涉及设置一个新的表实例，并在其上调用以下函数：

+   `addColumn`：此函数用于定义每个表列，并接受以下五个参数：

+   `name`：这是列的名称

+   `type`：这是数据存储类型（`int`，`varchar`，`text`等）

+   `size`：这是列的长度

+   `options`：这是用于数据存储的附加选项数组

+   `Comment`：这是列的描述

+   `addIndex`：此函数用于定义特定表的索引，并接受以下三个参数：

+   `index`：这是一个索引名称

+   `columns`：这可以是一个包含单个列名的字符串，也可以是包含多个列名的数组

+   `options`：这是用于数据存储的附加选项数组

+   `addForeginKey`：此函数用于定义外键关系，并接受以下六个参数：

+   `fkName`：这是一个外键名称

+   `column`：这是一个外键列名

+   `refTable`：这是一个参考表名。

+   `refColumn`：这是一个参考表列名

+   `onDelete`：这是在删除行时要执行的操作

+   `onUpdate`：这是在更新行时要执行的操作

创建我们每个表的代码基本上由这三个函数组成，在每个表定义之后，执行以下代码：

```php
$installer->getConnection()->createTable($table);
```

这告诉我们的数据库适配器将我们的代码转换为 SQL 并运行它针对数据库。有一件重要的事情要注意；那就是，代码不是提供或硬编码数据库名称，而是调用以下代码：

```php
$installer->getTable('mdg_giftregistry/entity')
```

这是我们在`config.xml`文件中之前定义的表别名。要完成我们的安装程序，我们需要为我们的每个实体创建一个`newTable`实例。

### 注意

这里有一个挑战给你。使用您的安装程序脚本创建缺失的表。要查看完整代码和完整分解的答案，请访问[`www.magedevguide.com/challenge/chapter4/1`](http://www.magedevguide.com/challenge/chapter4/1)。

数据脚本可用于填充我们的表；在我们的情况下，这将有助于设置一些基本事件类型。

首先，我们需要在`data`文件夹下创建一个数据安装脚本；正如我们之前提到的，结构与 SQL 文件夹非常相似，唯一的区别是我们将数据前缀附加到匹配的安装/升级脚本上。要这样做，请按照以下步骤进行：

1.  导航到模块数据文件夹`app/code/local/Mdg/Giftregistry/data/`。

1.  基于资源创建一个新目录；在这种情况下，它将是`mdg_giftregistry_setup`。

1.  在`mdg_giftregistry_setup`下，创建一个名为`data-install-0.1.0.php`的文件。

1.  将以下代码复制到`data-install-0.1.0.php`文件中（文件位置为`app/code/local/Mdg/Giftregistry/data/mdg_giftregistry_setup/data-install-0.1.0.php`）：

```php
<?php
$registryTypes = array(
    array(
        'code' => 'baby_shower',
        'name' => 'Baby Shower',
        'description' => 'Baby Shower',
        'store_id' => Mage_Core_Model_App::ADMIN_STORE_ID,
        'is_active' => 1,
    ),
    array(
        'code' => 'wedding',
        'name' => 'Wedding',
        'description' => 'Wedding',
        'store_id' => Mage_Core_Model_App::ADMIN_STORE_ID,
        'is_active' => 1,
    ),
    array(
        'code' => 'birthday',
        'name' => 'Birthday',
        'description' => 'Birthday',
        'store_id' => Mage_Core_Model_App::ADMIN_STORE_ID,
        'is_active' => 1,
    ),
);

foreach ($registryTypes as $data) {
    Mage::getModel('mdg_giftregistry/type')
        ->addData($data)
        ->setStoreId($data['store_id'])
        ->save();
}
```

让我们仔细看一下`data-install-0.1.0.php`脚本上的最后一个条件块：

```php
foreach ($registryTypes as $data) {
    Mage::getModel('mdg_giftregistry/type')
        ->addData($data)
        ->setStoreId($data['store_id'])
        ->save();
}
```

现在，如果我们刷新我们的 Magento 安装，错误应该消失，如果我们仔细看`mdg_giftregistry_type`表，我们应该看到以下记录：

![创建安装程序脚本](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060_04_03.jpg)

正如我们之前学到的，安装和数据脚本将在我们的模块第一次安装时运行。但在 Magento 已经认为我们的模块已安装的情况下会发生什么呢？

由于模块已经在`core_resource`表中注册，安装脚本将不会再次运行，除非 Magento 检测到扩展的版本更改。这对于处理扩展的多个发布版本非常有用，但对于开发目的并不是很实用。

幸运的是，很容易欺骗 Magento 再次运行我们的扩展安装脚本。我们只需要删除`core_resource`表中的相应条目。要这样做，请按照以下步骤操作：

1.  打开你的 MySQL 控制台；如果你正在使用我们的 Vagrant 盒子，你可以通过输入`mysql`来打开它。

1.  一旦我们在 MySQL shell 中，我们需要选择我们的工作数据库；在我们的情况下，它是`ce1702_magento`。

1.  最后，我们需要使用以下查询进入`core_resource`表：

```php
**mysql> DELETE FROM `core_resource` WHERE `code` =  'mdg_giftregistry_setup'**

```

## 我们学到了什么？

到目前为止，我们已经学会了：

+   为我们的 Magento 模块创建基本目录结构

+   配置文件的角色和重要性

+   创建模型和设置资源

+   安装、升级和数据脚本的角色和顺序

### 注意

这是一个挑战给你。尝试通过将实体转换为 EAV 模型来进一步改进我们模块的模型结构；这将需要修改安装脚本和资源模型。要查看完整的代码和详细的分解，请访问[`www.magedevguide.com/challenge/chapter4/2`](http://www.magedevguide.com/challenge/chapter4/2)。

# 设置我们的路由

现在我们能够通过使用我们的模型保存和操作数据，我们需要为客户提供一种与实际礼品注册互动的方式；这是我们的第一步。我们需要在前端创建有效的路由或 URL。

就像 Magento 中的许多事情一样，这由配置文件控制。路由将把 URL 转换为有效的控制器、动作和方法。

打开我们的`config.xml`文件。文件位置是`app/code/local/Mdg/Giftregistry/etc/config.xml`。参考以下代码：

```php
<config>
…
    <frontend>
        <routers>
            <mdg_giftregistry>
                <use>standard</use>
                <args>
                    <module>Mdg_Giftregistry</module>
                    <frontName>giftregistry</frontName>
                </args>
            </mdg_giftregistry>
        </routers>
    </frontend>
…
</config>
```

让我们分解一下我们刚刚添加的配置代码：

+   `<frontend>`：以前，我们将所有配置添加到全局范围内；由于我们希望我们的路由只在前端可用，我们需要在前端范围内声明我们的自定义路由

+   `<routers>`：这是包含我们自定义路由配置的容器标记

+   `<mdg_giftregistry>`：此标记的命名约定是匹配模块名称，并且是我们路由的唯一标识符

+   `<frontName>`：正如我们在第二章中学到的，*Magento 开发人员基础知识*，Magento 将 URL 分解为`http://localhost.com /frontName/actionControllerName/actionMethod/`。

一旦我们定义了我们的路由配置，我们需要创建一个实际的控制器来处理所有传入的请求。

## 索引控制器

我们的第一步是在我们的模块控制器目录下创建`IndexController`。如果没有指定控制器名称，Magento 将始终尝试加载`IndexController`。

文件位置是`app/code/local/Mdg/Giftregistry/controllers/Index.php`。参考以下代码：

```php
<?php 
class Mdg_Giftregistry_IndexController extends Mage_Core_Controller_Front_Action
{
     public function indexAction()
  {
    echo 'This is our test controller';
     }
}
```

创建我们的文件后，如果我们转到`http://localhost.com/giftregistry/index/index`，我们应该看到一个空白页面，上面有一条消息，说**这是我们的测试控制器**。这是因为我们没有正确加载我们的客户控制器的布局。文件位置是`app/code/local/Mdg/Giftregistry/controllers/IndexController.php`。我们需要将我们的动作代码更改为：

```php
<?php 
class Mdg_Giftregistry_IndexController extends Mage_Core_Controller_Front_Action
{
     public function indexAction()
  {
    $this->loadLayout();
    $this->renderLayout();
     }
}
```

在深入控制器动作内部发生的情况之前，让我们创建其余的控制器和相应的动作。

我们将需要一个控制器来处理客户的基本操作，以便他们能够创建、管理和删除他们的注册表。此外，我们还需要一个搜索控制器，以便家人和朋友可以找到匹配的礼品注册表，最后，我们还需要一个查看控制器来显示注册表的详细信息。

我们的第一步将是向索引控制器添加剩余的动作（文件位置为`app/code/local/Mdg/Giftregistry/controllers/IndexController.php`）：

```php
<?php
class Mdg_Giftregistry_IndexController extends Mage_Core_Controller_Front_Action
{
    public function indexAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }

    public function deleteAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }

    public function newAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }

    public function editAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }

    public function newPostAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }

    public function editPostAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }
}
```

在我们开始向索引控制器添加所有逻辑之前，我们需要采取额外的步骤，以防止未登录的客户访问`giftregistry`功能。Magento 前端控制器已经非常有用，用于处理这一点；它被称为`preDispatch()`函数，在控制器中的任何其他动作之前执行。

打开您的`IndexController.php`并在类的开头添加以下代码。

文件位置为`app/code/local/Mdg/Giftregistry/controllers/IndexController.php`。参考以下代码：

```php
<?php
class Mdg_Giftregistry_IndexController extends Mage_Core_Controller_Front_Action
{
    public function preDispatch()
    {
        parent::preDispatch();
        if (!Mage::getSingleton('customer/session')->authenticate($this)) {
            $this->getResponse()->setRedirect(Mage::helper('customer')->getLoginUrl());
            $this->setFlag('', self::FLAG_NO_DISPATCH, true);
        }
    }
…
```

现在，如果我们尝试加载`http://localhost.com/giftregistry/index/index`，我们将被重定向到登录页面，除非我们已登录到前端。

我们的下一步将是向每个控制器动作添加所有逻辑，以便控制器可以正确处理创建、更新和删除。

索引、新建和编辑动作主要用于加载和呈现布局，因此在控制器`newPostAction()`、`editPostAction()`和`deleteAction()`中涉及的逻辑不多；另一方面，它们处理了更繁重和更复杂的逻辑。

让我们开始`newPostAction()`。这个动作用于处理从`newAction()`表单接收到的数据。为此，请按照以下步骤操作：

1.  打开`IndexController.php`。

1.  我们将添加到动作的第一件事是一个`if`语句，以检查请求是否是 post 请求，我们可以使用以下代码检索到：

```php
$this->getRequest()->isPost()
```

1.  除此之外，我们还希望检查请求是否有实际数据；为此，我们可以使用以下代码：

```php
$this->getRequest()->getParams()
```

一旦我们验证了请求是一个合适的请求，并且我们正在接收数据，我们需要实际创建礼品注册。为此，我们将通过以下步骤在我们的注册表模型中添加一个新函数：

1.  打开注册表实体模型。

1.  创建一个名为`updateRegistryData()`的新函数，并确保函数接受两个参数：`$customer`和`$data`。

1.  文件位置为`app/code/local/Mdg/Giftregistry/Model/Entity.php`。在此函数内添加以下代码：

```php
public function updateRegistryData(Mage_Customer_Model_Customer $customer, $data)
{
    try{
        if(!empty($data))
        {
            $this->setCustomerId($customer->getId());
            $this->setWebsiteId($customer->getWebsiteId());
            $this->setTypeId($data['type_id']);
            $this->setEventName($data['event_name']);
            $this->setEventDate($data['event_date']);
            $this->setEventCountry($data['event_country']);
            $this->setEventLocation($data['event_location']);
        }else{
            throw new Exception("Error Processing Request: Insufficient Data Provided");
        }
    } catch (Exception $e){
        Mage::logException($e);
    }
    return $this;
}
```

这个函数将通过将表单数据添加到注册表对象的当前实例来帮助我们，这意味着我们需要在我们的控制器内创建一个实例。让我们把我们的控制器代码放在一起：

文件位置为`app/code/local/Mdg/Giftregistry/controllers/IndexController.php`。参考以下代码片段：

```php
public function newPostAction()
{
    try {
        $data = $this->getRequest()->getParams();
        $registry = Mage::getModel('mdg_giftregistry/entity');
        $customer = Mage::getSingleton('customer/session')->getCustomer();

        if($this->getRequest()->getPost() && !empty($data)) {
            $registry->updateRegistryData($customer, $data);
            $registry->save();
            $successMessage = Mage::helper('mdg_giftregistry')->__('Registry Successfully Created');
            Mage::getSingleton('core/session')->addSuccess($successMessage);
        }else{
            throw new Exception("Insufficient Data provided");
        }
    } catch (Mage_Core_Exception $e) {
        Mage::getSingleton('core/session')->addError($e->getMessage());
        $this->_redirect('*/*/');
    }
    $this->_redirect('*/*/');
}
```

我们已经创建了一个非常基本的控制器动作，它将处理注册表的创建并处理大部分可能的异常。

让我们继续创建`editPostAction`；这个动作与`newPostAction`非常相似。主要区别在于，在`editPostAction`的情况下，我们正在处理一个已经存在的注册表记录，因此在设置数据之前，我们需要添加一些验证。

文件位置为`app/code/local/Mdg/Giftregistry/controllers/IndexController.php`。让我们更仔细地看一下以下动作代码：

```php
public function editPostAction()
{
    try {
        $data = $this->getRequest()->getParams();
        $registry = Mage::getModel('mdg_giftregistry/entity');
        $customer = Mage::getSingleton('customer/session')->getCustomer();

        if($this->getRequest()->getPosts() && !empty($data) )
        {
            $registry->load($data['registry_id']);
            if($registry){
                $registry->updateRegistryData($customer, $data);
                $registry->save();
                $successMessage =  Mage::helper('mdg_giftregistry')->__('Registry Successfully Saved');
                Mage::getSingleton('core/session')->addSuccess($successMessage);
            }else {
                throw new Exception("Invalid Registry Specified");
            }
        }else {
            throw new Exception("Insufficient Data provided");
        }
    } catch (Mage_Core_Exception $e) {
        Mage::getSingleton('core/session')->addError($e->getMessage());
        $this->_redirect('*/*/');
    }
    $this->_redirect('*/*/');
}
```

正如我们所看到的，这段代码与我们的`newPostAction()`控制器几乎相同，关键区别在于它在更新数据之前尝试加载现有的注册表。

### 注意

这里有一个挑战给你。由于`editPostAction()`和`newPostAction()`之间的代码非常相似，尝试将两者合并为一个可以重复使用的单个 post 操作。要查看完整代码和完整分解的答案，请访问[`www.magedevguide.com/challenge/chapter4/3`](http://www.magedevguide.com/challenge/chapter4/3)。

要完成`IndexController`，我们需要添加一个允许我们删除特定注册记录的操作；为此，我们将使用`deleteAction()`。

由于 Magento ORM 系统，这个过程非常简单，因为 Magento 模型继承了`delete()`函数，正如其名称所示，它将简单地删除该特定模型实例。

文件位置为`app/code/local/Mdg/Giftregistry/controllers/IndexController.php`。在`IndexController`中，添加以下代码：

```php
public function deleteAction()
{
    try {
        $registryId = $this->getRequest()->getParam('registry_id');
        if($registryId && $this->getRequest()->getPost()){
            if($registry = Mage::getModel('mdg_giftregistry/entity')->load($registryId))
            {
                $registry->delete();
                $successMessage =  Mage::helper('mdg_giftregistry')->__('Gift registry has been succesfully deleted.');
                Mage::getSingleton('core/session')->addSuccess($successMessage);
            }else{
                throw new Exception("There was a problem deleting the registry");
            }
        }
    } catch (Exception $e) {
        Mage::getSingleton('core/session')->addError($e->getMessage());
        $this->_redirect('*/*/');
    }
}
```

我们删除控制器中要注意的重要操作如下：

1.  我们检查我们的操作是否是正确类型的请求。

1.  我们实例化注册对象并验证它是否有效。

1.  最后，我们在注册实例上调用`delete()`函数。

你可能已经注意到，由于我们犯了一个严重的遗漏，现在没有办法将实际产品添加到购物车中。

我们现在将跳过这个特定的操作，并且在我们更好地理解所涉及的块和布局以及它与我们的自定义控制器如何交互之后再创建它。

## 搜索控制器

现在我们有一个可以处理大部分修改实际注册的逻辑的工作`IndexController`，我们将创建的下一个控制器是`SearchController`。要这样做，请按照以下步骤进行：

1.  在 controllers 目录下创建一个名为`SearchController`的新控制器。

1.  文件位置为`app/code/local/Mdg/Giftregistry/controllers/SearchController.php`。将以下代码复制到搜索控制器中：

```php
<?php
class Mdg_Giftregistry_SearchController extends Mage_Core_Controller_Front_Action
{
    public function indexAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }
    public function resultsAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }
}
```

我们现在将暂时留下`indexAction`，并且将专注于`resultsAction()`中涉及的逻辑，它将获取搜索参数并加载注册集合。

文件位置为`app/code/local/Mdg/Giftregistry/controllers/SearchController.php`。让我们看一下完整的操作代码并分解它：

```php
public function resultsAction()
{
    $this->loadLayout();
    if ($searchParams = $this->getRequest()->getParam('search_params')) {
        $results = Mage::getModel('mdg_giftregistry/entity')->getCollection();
        if($searchParams['type']){
            $results->addFieldToFilter('type_id', $searchParams['type']);
        }
        if($searchParams['date']){
            $results->addFieldToFilter('event_date', $searchParams['date']);
        }
        if($searchParams['location']){
            $results->addFieldToFilter('event_location', $searchParams['location']);
        }
        $this->getLayout()->getBlock('mdg_giftregistry.search.results')
            ->setResults($results);
    }
    $this->renderLayout();
    return $this;
}
```

与以前的操作一样，我们获取请求参数，但在这种特殊情况下，我们加载了一个礼品注册集合，并为每个可用字段应用字段过滤器。一个值得注意的是，这是我们第一次直接从 Magento 控制器与布局交互。

```php
$this->getLayout()->getBlock('mdg_giftregistry.search.results')
        ->setResults($results);
```

我们在这里做的是使加载的注册集合可用于特定的块实例。

## 视图控制器

最后，我们需要一个控制器，允许显示注册详细信息，无论客户是否已登录。请按照以下步骤进行：

1.  在 controllers 目录下创建一个名为`ViewController`的新控制器。

1.  打开我们刚创建的控制器，并参考以下占位符代码（文件位置为`app/code/local/Mdg/Giftregistry/controllers/ViewController.php`）：

```php
<?php
class Mdg_Giftregistry_ViewController extends Mage_Core_Controller_Front_Action
{
    public function viewAction()
    {
        $registryId = $this->getRequest()->getParam('registry_id');
        if($registryId){
            $entity = Mage::getModel('mdg_giftregistry/entity');
            if($entity->load($registryId))
            {
                Mage::register('loaded_registry', $entity);
                $this->loadLayout();
                $this->_initLayoutMessages('customer/session');
                $this->renderLayout();
                return $this;
            } else {
                $this->_forward('noroute');
                return $this;
            }
        }
    }
}
```

因此，我们在这里使用了一个新的函数`Mage::register()`，它设置了一个全局变量，我们可以在应用程序流程中的任何方法中稍后检索。这个函数是 Magento Registry 模式的一部分，由以下三个函数组成：

+   `Mage::register()`: 这个函数用于设置全局变量

+   `Mage::unregister()`: 这个函数用于取消设置全局变量

+   `Mage::registry()`: 这个函数用于检索全局变量

在这种情况下，我们使用注册功能来在应用程序流程的更后面以及我们接下来将要创建的视图块中提供对注册实体的访问。

# 块和布局

正如我们在第二章中所学到的，*Magento 开发人员的基础知识*，Magento 将其视图层分为块、模板和布局文件。块是处理逻辑部分的对象。模板是`phtml`文件，是 HTML 和 PHP 代码的混合。布局文件是控制块位置的 XML 文件。

每个模块都有自己的布局文件，负责更新该特定模块的布局。我们需要按照以下步骤开始为我们的模块创建一个布局文件：

1.  导航至`app/design/frontend/base/default/layout/`。

1.  创建一个名为`mdg_giftregistry.xml`的文件。

1.  添加以下代码（文件位置为`app/design/frontend/base/default/layout/mdg_giftregistry.xml`）：

```php
<layout version="0.1.0">
  <mdg_giftregistry_index_index>
  </mdg_giftregistry_index_index>  

  <mdg_giftregistry_index_new>
  </mdg_giftregistry_index_new>

  <mdg_giftregistry_index_edit>
  </mdg_giftregistry_index_edit>

  <mdg_giftregistry_view_view>
  </mdg_giftregistry_view_view>

  <mdg_giftregistry_search_index>
  </mdg_giftregistry_search_index>

  <mdg_giftregistry_search_results>
  </mdg_giftregistry_search_results>
</layout>
```

### 注意

请注意，通过将我们的模板和布局添加到 base/default 主题，我们将使我们的模板和布局对所有商店和主题可用。

如果我们仔细看刚刚粘贴的 XML，我们可以看到我们有一个默认的`<xml>`标签和几组其他标签。正如我们之前提到的，在 Magento 中，路由由前端名称、控制器和操作组成。

布局文件中的每个 XML 标签代表我们的控制器和操作之一；例如，`<giftregistry_index_index>`将控制我们的`IndexController`操作的布局；Magento 为每个页面分配一个唯一的句柄。

为了让 Magento 识别我们的布局文件，我们需要按照以下步骤在`config.xml`文件中声明布局文件：

1.  导航至`extension etc/`文件夹。

1.  打开`config.xml`。

1.  在`<frontend>`节点内添加以下代码（文件位置为`app/design/frontend/base/default/layout/mdg_giftregistry.xml`）：

```php
<frontend>
   <layout>
       <updates>
           <mdg_giftregistry module="mdg_giftregistry">
               <file>mdg_giftregistry.xml</file>
           </mdg_giftregistry>
       </updates>
   </layout>
   …
</frontend>
```

## IndexController 块和视图

与之前一样，我们将从构建索引控制器开始。让我们定义每个操作需要定义的模板和块：

+   **索引**：这是当前客户可用注册表的列表

+   **新**：这提供了一个捕获注册表信息的新表单

+   **编辑**：这会加载特定的注册表数据并将其加载到表单中

对于索引操作，我们需要创建一个名为`List.php`的新块。让我们按照以下步骤开始创建注册表列表块：

1.  导航至`app/code/local/Mdg/Giftregistry/Block/`。

1.  创建一个名为`List.php`的文件。

1.  复制以下代码（文件位置为`app/code/local/Mdg/Giftregistry/Block/List.php`）。

```php
<?php
class Mdg_Giftregistry_Block_list extends Mage_Core_Block_Template
{
    public function getCustomerRegistries()
    {
        $collection = null;
        $currentCustomer = Mage::getSingleton('customer/session')->getCustomer();
        if($currentCustomer)
        {
            $collection = Mage::getModel('mdg_giftregistry/entity')->getCollection()
                ->addFieldToFilter('customer_id', $currentCustomer->getId());
        }
        return $collection;
    }
}
```

前面的代码声明了我们将在`IndexController`中使用的列表块。块声明了`getCustomerRegistries()`方法，该方法将检查当前客户并尝试基于该客户检索注册表集合。

现在我们创建了一个新的块，我们需要将其添加到我们的布局 XML 文件中：

1.  打开`mdg_giftregistry.xml`。

1.  在`<mdg_gifregistry_index_index>`内添加以下代码（文件位置为`app/design/frontend/base/default/layout/mdg_giftregistry.xml`）：

```php
<reference name="content">
    <block name="giftregistry.list" type="mdg_giftregistry/list" template="mdg/list.phtml" as="giftregistry_list"/>
</reference>
```

在布局中，我们声明了我们的块；在该声明内，我们设置了块名称、模板和类型。如果我们现在尝试加载索引控制器页面，由于我们还没有创建我们的模板文件，我们应该会看到有关缺少模板的错误。

让我们创建模板文件：

1.  导航至`design/frontend/base/default/template/`。

1.  创建`mdg/`文件夹。

1.  在该文件夹内，创建一个名为`list.phtml`的文件（文件位置为`app/design/frontend/base/default/template/mdg/list.phtml`）：

```php
<?php
$_collection = $this->getCustomerRegistries();
?>
<div class="customer-list">
    <ul>
        <?php foreach($_collection as $registry): ?>
            <li>
                <h3><?php echo $registry->getEventName(); ?></h3>
                <p><strong><?php echo $this->__('Event Date:') ?> <?php echo $registry->getEventDate(); ?></strong></p>
                <p><strong><?php echo $this->__('Event Location:') ?> <?php echo $registry->getEventLocation(); ?></strong></p>
                <a href="<?php echo $this->getUrl('giftregistry/view/view', array('_query' => array('registry_id' => $registry->getEntityId()))) ?>">
                    <?php echo $this->__('View Registry') ?>
                </a>
            </li>
        <?php endforeach; ?>
    </ul>
</div>
```

这是我们第一次生成`.phtml`文件。正如我们之前提到的，`.phtml`文件只是 PHP 和 HTML 代码的组合。

在`list.phtml`文件中，我们要做的第一件事是通过调用`getCustomerRegistries()`方法加载一个集合；需要注意的一点是，我们实际上是在调用`$this->getCustomerRegistries()`，因为每个模板都分配给一个特定的块。

我们缺少一些重要的东西，如下所示：

+   如果当前客户没有注册表，我们只会显示一个空的无序列表。

+   没有链接来删除或编辑特定的注册表

检查集合是否有注册表的一个快速方法是调用`count`函数，并在集合实际为空时显示错误消息。

文件位置为`app/design/frontend/base/default/template/mdg/list.phtml`。参考以下代码：

```php
<?php
    $_collection = $this->getCustomerRegistries();
?>
<div class="customer-list">
    <?php if(!$_collection->count()): ?>
        <h2><?php echo $this->__('You have no registries.') ?></h2>
        <a href="<?php echo $this->getUrl('giftregistry/index/new') ?>">
            <?php echo $this->__('Click Here to create a new Gift Registry') ?>
        </a>
    <?php else: ?>
        <ul>
            <?php foreach($_collection as $registry): ?>
                <li>
                    <h3><?php echo $registry->getEventName(); ?></h3>
                    <p><strong><?php echo $this->__('Event Date:') ?> <?php echo $registry->getEventDate(); ?></strong></p>
                    <p><strong><?php echo $this->__('Event Location:') ?> <?php echo $registry->getEventLocation(); ?></strong></p>
                    <a href="<?php echo $this->getUrl('giftregistry/view/view', array('_query' => array('registry_id' => $registry->getEntityId()))) ?>">
                        <?php echo $this->__('View Registry') ?>
                    </a>
                    <a href="<?php echo $this->getUrl('giftregistry/index/edit', array('_query' => array('registry_id' => $registry->getEntityId()))) ?>">
                        <?php echo $this->__('Edit Registry') ?>
                    </a>
                    <a href="<?php echo $this->getUrl('giftregistry/index/delete', array('_query' => array('registry_id' => $registry->getEntityId()))) ?>">
                        <?php echo $this->__('Delete Registry') ?>
                    </a>

                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</div>
```

我们添加了一个新的`if`语句来检查集合计数是否为空，并添加了一个链接到`IndexController`编辑操作。最后，如果没有要显示的注册表，我们将显示一个错误消息，链接到新操作。

让我们继续添加新操作的块和模板：

1.  打开`mdg_giftregistry.xml`布局文件。

1.  在`<mdg_gifregistry_index_new>`节点内添加以下代码（文件位置为`app/design/frontend/base/default/layout/mdg_giftregistry.xml`）：

```php
<reference name="content">
    <block name="giftregistry.new" type="core/template" template="mdg/new.phtml" as="giftregistry_new"/>
</reference>
```

由于我们只是显示一个表单来将注册表信息发布到`newPostAction()`，我们只是创建一个带有包含表单代码的自定义模板文件的 core/template 块。我们的模板文件将如下所示。

文件位置为`app/design/frontend/base/default/template/mdg/new.phtml`：

```php
<?php $helper = Mage::helper('mdg_giftregistry'); ?>
<form action="<?php echo $this->getUrl('giftregistry/index/newPost/') ?>" method="post" id="form-validate">
    <fieldset>
        <?php echo $this->getBlockHtml('formkey')?>
        <ul class="form-list">
            <li>
                <label for="type_id"><?php echo $this->__('Event type') ?></label>
                <select name="type_id" id="type_id">
                    <?php foreach($helper->getEventTypes() as $type): ?>
                        <option id="<?php echo $type->getTypeId(); ?>" value="<?php echo $type->getCode(); ?>">
                            <?php echo $type->getName(); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </li>
            <li class="field">
                <input type="text" name="event_name" id="event_name" value="" title="Event Name"/>
                <label class="giftreg" for="event_name"><?php echo $this->__('Event Name') ?></label>
            </li>
            <li class="field">
                <input type="text" name="event_location" id="event_location" value="" title="Event Location"/>
                <label class="giftreg" for="event_location"><?php echo $this->__('Event Location') ?></label>
            </li>
            <li class="field">
                <input type="text" name="event_country" id="event_country" value="" title="Event Country"/>
                <label class="giftreg" for="event_country"><?php echo $this->__('Event Country') ?></label>
            </li>
        </ul>
        <div class="buttons-set">
            <button type="submit" title="Save" class="button">
                <span>
                    <span><?php echo $this->__('Save') ?></span>
                </span>
            </button>
        </div>
    </fieldset>
</form>
<script type="text/javascript">
    //<![CDATA[
    var dataForm = new VarienForm('form-validate', true);
    //]]>
</script>
```

这次我们在这里做一些新的事情。我们正在调用一个帮助程序；帮助程序是一个包含可以从块、模板、控制器等中重复使用的方法的类。在我们的情况下，我们正在创建一个帮助程序，它将检索所有可用的注册类型。按照以下步骤进行：

1.  导航到`app/code/local/Mdg/Giftregistry/Helper`。

1.  打开`Data.php`类。

1.  在其中添加以下代码（文件位置为`app/code/local/Mdg/Giftregistry/Helper/Data.php`）：

```php
<?php
class Mdg_Giftregistry_Helper_Data extends Mage_Core_Helper_Abstract {

public function getEventTypes()
    {
        $collection = Mage::getModel('mdg_giftregistry/type')->getCollection();
        return $collection;
    }
}
```

最后，我们需要设置编辑模板；编辑模板将与新模板完全相同，但有一个主要区别。我们将检查加载的注册表是否存在，并预填充我们字段的值。

文件位置为`app/design/frontend/base/default/template/mdg/edit.phtml`。参考以下代码：

```php
<?php
    $helper = Mage::helper('mdg_giftregistry');
    $loadedRegistry = Mage::getSingleton('customer/session')->getLoadedRegistry();
?>
<?php if($loadedRegistry): ?>
    <form action="<?php echo $this->getUrl('giftregistry/index/editPost/') ?>" method="post" id="form-validate">
        <fieldset>
            <?php echo $this->getBlockHtml('formkey')?>
            <input type="hidden" id="type_id" value="<?php echo $loadedRegistry->getTypeId(); ?>" />
            <ul class="form-list">
                <li class="field">
                    <label class="giftreg" for="event_name"><?php echo $this->__('Event Name') ?></label>
                    <input type="text" name="event_name" id="event_name" value="<?php echo $loadedRegistry->getEventName(); ?>" title="Event Name"/>
                </li>
                <li class="field">
                    <label class="giftreg" for="event_location"><?php echo $this->__('Event Location') ?></label>
                    <input type="text" name="event_location" id="event_location" value="<?php echo $loadedRegistry->getEventLocation(); ?>" title="Event Location"/>
                </li>
                <li class="field">
                    <label class="giftreg" for="event_country"><?php echo $this->__('Event Country') ?></label>
                    <input type="text" name="event_country" id="event_country" value="<?php echo $loadedRegistry->getEventCountry(); ?>" title="Event Country"/>
                </li>
            </ul>
            <div class="buttons-set">
                <button type="submit" title="Save" class="button">
                    <span>
                        <span><?php echo $this->__('Save') ?></span>
                    </span>
                </button>
            </div>
        </fieldset>
    </form>
    <script type="text/javascript">
        //<![CDATA[
        var dataForm = new VarienForm('form-validate', true);
        //]]>
    </script>
<?php else: ?>
    <h2><?php echo $this->__('There was a problem loading the registry') ?></h2>
<?php endif; ?>
```

让我们继续添加编辑操作的块和模板：

1.  打开`mdg_giftregistry.xml`布局文件。

1.  在`<mdg_gifregistry_index_edit>`节点内添加以下代码（文件位置为`app/design/frontend/base/default/layout/mdg_giftregistry.xml`）：

```php
<reference name="content">
    <block name="giftregistry.edit" type="core/template" template="mdg/edit.phtml" as="giftregistry_edit"/>
</reference>
```

设置好后，我们可以尝试创建一对测试注册表并修改它们的属性。

### 注意

这里有一个挑战给你。与控制器一样，编辑和新表单可以合并为一个可重用的表单。尝试将它们合并以查看完整代码和完整分解的答案，请访问[`www.magedevguide.com/challenge/chapter4/4`](http://www.magedevguide.com/challenge/chapter4/4)。

## SearchController 块和视图

对于我们的搜索控制器，我们将需要一个用于我们的索引的搜索模板。对于结果，我们实际上可以通过简单地更改我们的控制器来重用注册表列表模板，按照以下步骤进行：

1.  导航到模板文件夹。

1.  创建一个名为`search.phtml`的文件。

1.  添加以下代码（文件位置为`app/design/frontend/base/default/template/mdg/search.phtml`）：

```php
<?php $helper = Mage::helper('mdg_giftregistry'); ?>
<form action="<?php echo $this->getUrl('giftregistry/search/results/') ?>" method="post" id="form-validate">
    <fieldset>
        <?php echo $this->getBlockHtml('formkey')?>
        <ul class="form-list">
            <li>
                <label for="type">Event type</label>
                <select name="type" id="type">
                    <?php foreach($helper->getEventTypes() as $type): ?>
                        <option id="<?php echo $type->getTypeId(); ?>" value="<?php echo $type->getCode(); ?>">
                            <?php echo $type->getName(); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </li>
            <li class="field">
                <label class="giftreg" for="name"><?php echo $this->__('Event Name') ?></label>
                <input type="text" name="name" id="name" value="" title="Event Name"/>
            </li>
            <li class="field">
                <label class="giftreg" for="location"><?php echo $this->__('Event Location') ?></label>
                <input type="text" name="location" id="location" value="" title="Event Location"/>
            </li>
            <li class="field">
                <label class="giftreg" for="country"><?php echo $this->__('Event Country') ?></label>
                <input type="text" name="country" id="country" value="" title="Event Country"/>
            </li>
        </ul>
        <div class="buttons-set">
            <button type="submit" title="Save" class="button">
                    <span>
                        <span><?php echo $this->__('Save') ?></span>
                    </span>
            </button>
        </div>
    </fieldset>
</form>
<script type="text/javascript">
    //<![CDATA[
    var dataForm = new VarienForm('form-validate', true);
    //]]>
</script>
```

有几件事情需要注意：

+   我们使用帮助程序模型来填充`Event`类型 ID

+   我们直接发布到搜索/结果

现在，让我们对布局文件进行适当的更改：

1.  打开`mdg_giftregistry.xml`。

1.  在`<mdg_gifregistry_search_index>`内添加以下代码（文件位置为`app/design/frontend/base/default/layout/mdg_giftregistry.xml`）：

```php
<reference name="content">
    <block name="giftregistry.search" type="core/template" template="mdg/search.phtml" as="giftregistry_search"/>
</reference>
```

对于搜索结果，我们不需要创建新的块类型，因为我们直接将结果集合传递给块。在布局中，我们的更改将是最小的，我们可以重用列表块来显示搜索注册表结果。

但是，我们确实需要在控制器中进行更改。我们需要将函数从`setResults()`更改为`setCustomerRegistries()`。

文件位置为`app/code/local/Mdg/Giftregistry/controllers/SearchController.php`。参考以下代码：

```php
public function resultsAction()
{
    $this->loadLayout();
    if ($searchParams = $this->getRequest()->getParam('search_params')) {
        $results = Mage::getModel('mdg_giftregistry/entity')->getCollection();
        if($searchParams['type']){
            $results->addFieldToFilter('type_id', $searchParams['type']);
        }
        if($searchParams['date']){
            $results->addFieldToFilter('event_date', $searchParams['date']);
        }
        if($searchParams['location']){
            $results->addFieldToFilter('event_location', $searchParams['location']);
        }
        $this->getLayout()->getBlock('mdg_giftregistry.search.results')
            ->setCustomerRegistries($results);
    }
    $this->renderLayout();
    return $this;
}
```

最后，让我们按照以下步骤更新布局文件：

1.  打开`mdg_giftregistry.xml`。

1.  在`<mdg_gifregistry_search_results>`内添加以下代码（文件位置为`app/design/frontend/base/default/layout/mdg_giftregistry.xml`）：

```php
<reference name="content">
    <block name="giftregistry.results" type="mdg_giftregistry/list" template="mdg/list.phtml"/>
</reference>
```

这将是我们的`SearchController`模板的结束；然而，我们的搜索结果显示了一个问题。对于注册表的删除和编辑链接，我们需要一种方法来仅限制这些链接只对所有者可见。

我们可以使用以下`Helper`函数来实现：

文件位置为`app/code/local/Mdg/Giftregistry/Helper/Data.php`。参考以下代码：

```php
public function isRegistryOwner($registryCustomerId)
{
    $currentCustomer = Mage::getSingleton('customer/session')->getCustomer();
    if($currentCustomer && $currentCustomer->getId() == $registryCustomerId)
    {
        return true;
    }
    return false;
}
```

让我们更新我们的模板，以使用新的`helper`方法。

文件位置为`app/design/frontend/base/default/template/mdg/list.phtml`。参考以下代码：

```php
<?php
    $_collection = $this->getCustomerRegistries();
    $helper = Mage::helper('mdg_giftregistry')
?>
<div class="customer-list">
    <?php if(!$_collection->count()): ?>
        <h2><?php echo $this->__('You have no registries.') ?></h2>
        <a href="<?php echo $this->getUrl('giftregistry/index/new') ?>">
            <?php echo $this->__('Click Here to create a new Gift Registry') ?>
        </a>
    <?php else: ?>
        <ul>
            <?php foreach($_collection as $registry): ?>
                <li>
                    <h3><?php echo $registry->getEventName(); ?></h3>
                    <p><strong><?php echo $this->__('Event Date:') ?> <?php echo $registry->getEventDate(); ?></strong></p>
                    <p><strong><?php echo $this->__('Event Location:') ?> <?php echo $registry->getEventLocation(); ?></strong></p>
                    <a href="<?php echo $this->getUrl('giftregistry/view/view', array('_query' => array('registry_id' => $registry->getEntityId()))) ?>">
                        <?php echo $this->__('View Registry') ?>
                    </a>
                    <?php if($helper->isRegistryOwner($registry->getCustomerId())): ?>
                        <a href="<?php echo $this->getUrl('giftregistry/index/edit', array('_query' => array('registry_id' => $registry->getEntityId()))) ?>">
                            <?php echo $this->__('Edit Registry') ?>
                        </a>
                        <a href="<?php echo $this->getUrl('giftregistry/index/delete', array('_query' => array('registry_id' => $registry->getEntityId()))) ?>">
                            <?php echo $this->__('Delete Registry') ?>
                        </a>
                    <?php endif; ?>

                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</div>
```

## ViewController 块和视图

对于我们的视图，我们只需要创建一个新的模板文件和在`layout.xml`文件中创建一个新条目：

1.  导航到模板目录。

1.  创建一个名为`view.phtml`的模板。

1.  添加以下代码（文件位置为`app/design/frontend/base/default/template/mdg/view.phtml`）：

```php
<?php $registry = Mage::registry('loaded_registry'); ?>
<h3><?php echo $registry->getEventName(); ?></h3>
<p><strong><?php $this->__('Event Date:') ?> <?php echo $registry->getEventDate(); ?></strong></p>
<p><strong><?php $this->__('Event Location:') ?> <?php echo $registry->getEventLocation(); ?></strong></p>
```

1.  更新布局 XML 文件`<mdg_gifregistry_view_view>`。

```php
<reference name="content">
    <block name="giftregistry.view" type="core/template" template="mdg/view.phtml" as="giftregistry_view"/>
</reference>
```

### 注意

这里有一个挑战给你。改进视图表单，以便在没有实际加载的注册表时返回错误。要查看完整代码和详细分解的答案，请访问[`www.magedevguide.com/challenge/chapter4/5`](http://www.magedevguide.com/challenge/chapter4/5)。

## 将产品添加到注册表

我们几乎到了本章的结尾，但我们还没有涵盖如何向我们的注册表添加产品。由于本书篇幅有限，我决定将这一部分移到[`www.magedevguide.com/chapter6/adding-products-registry`](http://www.magedevguide.com/chapter6/adding-products-registry)。

# 总结

在本章中，我们涵盖了很多内容。我们学会了如何扩展 Magento 的前端以及如何处理路由和控制器。

Magento 布局系统允许我们修改和控制块，并在我们的商店上显示它。我们还开始使用 Magento 数据模型，并学会了如何使用它们，以及如何处理和操作我们的数据。

我们只是触及了前端开发和数据模型的表面。在下一章中，我们将更深入地扩展配置、模型和数据的主题，并在 Magento 后端探索和创建管理部分。


# 第五章：后端开发

在上一章中，我们为礼品注册表添加了所有前端功能。现在客户能够创建注册表并向客户注册表添加产品，并且通常可以完全控制自己的注册表。

在本章中，我们将构建所有商店所有者需要通过 Magento 后端管理和控制注册表的功能。

Magento 后端在许多方面可以被视为与 Magento 前端分开的应用程序；它使用完全不同的主题、样式和不同的基本控制器。

对于我们的礼品注册表，我们希望允许商店所有者查看所有客户注册表，修改信息，并添加和删除项目。在本章中，我们将涵盖以下内容：

+   使用配置扩展 Adminhtml

+   使用网格小部件

+   使用表单小部件

+   使用访问控制列表限制访问和权限

# 扩展 Adminhtml

`Mage_Adminhtml`是一个单一模块，通过使用配置提供 Magento 的所有后端功能。正如我们之前学到的，Magento 使用范围来定义配置。在上一章中，我们使用前端范围来设置我们自定义模块的配置。

要修改后端，我们需要在配置文件中创建一个名为`admin`的新范围。执行以下步骤来完成：

1.  打开`config.xml`文件，可以在`app/code/loca/Mdg/Giftregistry/etc/`位置找到。

1.  将以下代码添加到其中：

```php
<admin>
 <routers>
   <giftregistry>
     <use>admin</use>
       <args>
           <module>Mdg_Giftregistry_Adminhmtl</module>
           <frontName>giftregistry</frontName>
       </args>
   </giftregistry>
 </routers>
</admin>
```

这段代码与我们以前用来指定前端路由的代码非常相似；然而，通过这种方式声明路由，我们正在打破一个未写的 Magento 设计模式。

为了在后端保持一致，所有新模块都应该扩展主管理路由。

与以前的代码定义路由不同，我们正在创建一个全新的管理路由。通常情况下，除非您正在创建一个需要管理员访问但不需要 Magento 后端其余部分的新路由，否则不要在 Magento 后端这样做。管理员操作的回调 URL 就是这种情况的一个很好的例子。

幸运的是，有一种非常简单的方法可以在 Magento 模块之间共享路由名称。

### 注意

在 Magento 1.3 中引入了共享路由名称，但直到今天，我们仍然看到一些扩展没有正确使用这种模式。

让我们更新我们的代码：

1.  打开`config.xml`文件，可以在`app/code/loca/Mdg/Giftregistry/etc/`位置找到。

1.  使用以下代码更新路由配置：

```php
<admin>
 <routers>
   <adminhtml>
     <args>
       <modules>
         <mdg_giftregistry before="Mage_Adminhtml">Mdg_Giftregistry_Adminhtml</mdg_giftregistry>
       </modules>
     </args>
   </adminhtml>
 </routers>
</admin>
```

做出这些改变后，我们可以通过管理命名空间正确访问我们的管理控制器；例如，`http://magento.localhost.com/giftregistry/index`现在将是`http://magento.localhost.com/admin/giftregistry/index`。

我们的下一步将是创建一个新的控制器，我们可以用来管理客户注册表。我们将把这个控制器称为`GiftregistryController.php`。执行以下步骤来完成：

1.  导航到您的模块控制器文件夹。

1.  创建一个名为`Adminhtml`的新文件夹。

1.  在`app/code/loca/Mdg/Giftregistry/controllers/Adminhtml/`位置创建名为`GiftregistryController.php`的文件。

1.  将以下代码添加到其中：

```php
<?php
class Mdg_Giftregistry_Adminhtml_GiftregistryController extends Mage_Adminhtml_Controller_Action
{
    public function indexAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }

    public function editAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }

    public function saveAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }

    public function newAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }

    public function massDeleteAction()
    {
        $this->loadLayout();
        $this->renderLayout();
        return $this;
    }
}
```

请注意一个重要的事情：这个新控制器扩展了`Mage_Adminhtml_Controller_Action`而不是我们到目前为止一直在使用的`Mage_Core_Controller_Front_Action`。这样做的原因是`Adminhtml`控制器具有额外的验证，以防止非管理员用户访问它们的操作。

请注意，我们将我们的控制器放在`controllers/`目录内的一个新子文件夹中；通过使用这个子目录，我们可以保持前端和后端控制器的组织。这是一个被广泛接受的 Magento 标准实践。

现在，让我们暂时不管这个空控制器，让我们扩展 Magento 后端导航并向客户编辑页面添加一些额外的选项卡。

## 回到配置

到目前为止，我们已经看到，大多数情况下 Magento 由 XML 配置文件控制，后端布局也不例外。我们需要创建一个新的`adminhtml`布局文件。执行以下步骤来完成：

1.  导航到设计文件夹。

1.  创建一个名为`adminhtml`的新文件夹，并在其中创建以下文件夹结构：

+   `adminhtml/`

+   `--default/`

+   `----default/`

+   `------template/`

+   `------layout/`

1.  在`layout`文件夹内，让我们在位置`app/code/design/adminhtml/default/default/layout/`创建一个名为`giftregistry.xml`的新布局文件。

1.  将以下代码复制到布局文件中：

```php
<?xml version="1.0"?>
<layout version="0.1.0">
    <adminhtml_customer_edit>
        <reference name="left">
            <reference name="customer_edit_tabs">
                <block type="mdg_giftregistry/adminhtml_customer_edit_tab_giftregistry" name="tab_giftregistry_main" template="mdg_giftregistry/giftregistry/customer/main.phtml">
                </block>
                <action method="addTab">
                 <name>mdg_giftregistry</name>
              <block>tab_giftregistry_main</block>
          </action>
            </reference>
        </reference>
    </adminhtml_customer_edit>
</layout>
```

我们还需要将新的布局文件添加到`config.xml`模块中。执行以下步骤来完成：

1.  导航到`etc/`文件夹。

1.  打开`config.xml`文件，可以在位置`app/code/loca/Mdg/Giftregistry/etc/`找到。

1.  将以下代码复制到`config.xml`文件中：

```php
…
    <adminhtml>
        <layout>
            <updates>
                <mdg_giftregistry module="mdg_giftregistry">
                    <file>giftregistry.xml</file>
                </mdg_giftregistry>
            </updates>
        </layout>
    </adminhtml>
…
```

在布局内部，我们正在创建一个新的容器块，并声明一个包含此块的新选项卡。

让我们通过登录到 Magento 后端并打开**客户管理**，进入**客户** | **管理客户**，快速测试我们迄今为止所做的更改。

我们应该在后端得到以下错误：

![返回配置](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_05_01.jpg)

这是因为我们正在尝试添加一个尚未声明的块；为了解决这个问题，我们需要创建一个新的块类。执行以下步骤来完成：

1.  导航到块文件夹，并按照目录结构创建一个名为`Giftregistry.php`的新块类，位置在`app/code/loca/Mdg/Giftregistry/Block/Adminhtml/Customer/Edit/Tab/`。

1.  将以下代码添加到其中：

```php
<?php 
class Mdg_Giftregistry_Block_Adminhtml_Customer_Edit_Tab_Giftregistry
    extends Mage_Adminhtml_Block_Template
    implements Mage_Adminhtml_Block_Widget_Tab_Interface {

    public function __construct()
    {
        $this->setTemplate('mdg/giftregistry/customer/main.phtml');
        parent::_construct();
    }

    public function getCustomerId()
    {
        return Mage::registry('current_customer')->getId();
    }

    public function getTabLabel()
    {
        return $this->__('GiftRegistry List');
    }

    public function getTabTitle()
    {
        return $this->__('Click to view the customer Gift Registries');
    }

    public function canShowTab()
    {
        return true;
    }

    public function isHidden()
    {
        return false;
    }
}
```

这个块类有一些有趣的事情发生。首先，我们正在扩展一个不同的块类`Mage_Adminhtml_Block_Template`，并实现一个新的接口`Mage_Adminhtml_Block_Widget_Tab_Interface`。这样做是为了访问 Magento 后端的所有功能和功能。

我们还在类的构造函数中设置了块模板；同样在`getCustomerId`下，我们使用 Magento 全局变量来获取当前客户。

我们的下一步将是为此块创建相应的模板文件，否则我们将在块初始化时出现错误。

1.  在位置`app/code/design/adminhtml/default/default/template/mdg/giftregistry/customer/`创建一个名为`main.phtml`的模板文件。

1.  将以下代码复制到其中：

```php
<div class="entry-edit">
    <div class="entry-edit-head">
        <h4 class="icon-head head-customer-view"><?php echo $this->__('Customer Gift Registry List') ?></h4>
    </div>
    <table cellspacing="2" class="box-left">
        <tr>
            <td>
                Nothing here 
            </td>
        </tr>
    </table>
</div>
```

目前，我们只是向模板添加占位内容，以便我们实际上可以看到我们的选项卡在操作中；现在，如果我们转到后端的客户部分，我们应该看到一个新的选项卡可用，并且单击该选项卡将显示我们的占位内容。

到目前为止，我们已经修改了后端，并通过更改配置和添加一些简单的块和模板文件，向客户部分添加了**Customers**选项卡。但到目前为止，这还没有特别有用，所以我们需要一种方法来显示所有客户礼品注册在**礼品注册**选项卡下。

# 网格小部件

我们可以重用 Magento `Adminhtml`模块已经提供的块，而不必从头开始编写我们自己的网格块。

我们将要扩展的块称为网格小部件；网格小部件是一种特殊类型的块，旨在以特定的表格网格中呈现 Magento 对象的集合。

网格小部件通常呈现在网格容器内；这两个元素的组合不仅允许以网格形式显示我们的数据，还添加了搜索、过滤、排序和批量操作功能。执行以下步骤：

1.  导航到块`Adminhtml/`文件夹，并在位置`app/code/loca/Mdg/Giftregistry/Block/Adminhtml/Customer/Edit/Tab/`创建一个名为`Giftregistry/`的文件夹。

1.  在该文件夹内创建一个名为`List.php`的类。

1.  将以下代码复制到`Giftregistry/List.php`文件中：

```php
<?php
class Mdg_Giftregistry_Block_Adminhtml_Customer_Edit_Tab_Giftregistry_List extends Mage_Adminhtml_Block_Widget_Grid
{
    public function __construct()
    {
        parent::__construct();
        $this->setId('registryList');
        $this->setUseAjax(true);
        $this->setDefaultSort('event_date');
        $this->setFilterVisibility(false);
        $this->setPagerVisibility(false);
    }

    protected function _prepareCollection()
    {
        $collection = Mage::getModel('mdg_giftregistry/entity')
            ->getCollection()
            ->addFieldToFilter('main_table.customer_id', $this->getRequest()->getParam('id'));
        $this->setCollection($collection);
        return parent::_prepareCollection();
    }

    protected function _prepareColumns()
    {
        $this->addColumn('entity_id', array(
            'header'   => Mage::helper('mdg_giftregistry')->__('Id'),
            'width'    => 50,
            'index'    => 'entity_id',
            'sortable' => false,
        ));

        $this->addColumn('event_location', array(
            'header'   => Mage::helper('mdg_giftregistry')->__('Location'),
            'index'    => 'event_location',
            'sortable' => false,
        ));

        $this->addColumn('event_date', array(
            'header'   => Mage::helper('mdg_giftregistry')->__('Event Date'),
            'index'    => 'event_date',
            'sortable' => false,
        ));

        $this->addColumn('type_id', array(
            'header'   => Mage::helper('mdg_giftregistry')->__('Event Type'),
            'index'    => 'type_id',
            'sortable' => false,
        ));
        return parent::_prepareColumns();
    }
}
```

看看我们刚刚创建的类，只涉及三个函数：

+   `__construct()`

+   `_prepareCollection()`

+   `_prepareColumns()`

在`__construct`函数中，我们指定了关于我们的网格类的一些重要选项。我们设置了`gridId`；默认排序为`eventDate`，并启用了分页和过滤。

`__prepareCollection()`函数加载了一个由当前`customerId`过滤的注册表集合。这个函数也可以用来在我们的集合中执行更复杂的操作；例如，连接一个辅助表以获取有关客户或其他相关记录的更多信息。

最后，通过使用`__prepareColumns()`函数，我们告诉 Magento 应该显示哪些列和数据集的属性，以及如何渲染它们。

现在我们已经创建了一个功能性的网格块，我们需要对我们的布局 XML 文件进行一些更改才能显示它。执行以下步骤：

1.  打开`giftregistry.xml`文件，该文件位于`app/design/adminhtml/default/default/layout/`位置。

1.  进行以下更改：

```php
<?xml version="1.0"?>
<layout version="0.1.0">
    <adminhtml_customer_edit>
        <reference name="left">
            <reference name="customer_edit_tabs">
                <block type="mdg_giftregistry/adminhtml_customer_edit_tab_giftregistry" name="tab_giftregistry_main" template="mdg/giftregistry/customer/main.phtml">
                    <block type="mdg_giftregistry/adminhtml_customer_edit_tab_giftregistry_list" name="tab_giftregistry_list" as="giftregistry_list" />
                </block>
                <action method="addTab">
                    <name>mdg_giftregistry</name>
                    <block>mdg_giftregistry/adminhtml_customer_edit_tab_giftregistry</block>
                </action>
            </reference>
        </reference>
    </adminhtml_customer_edit>
</layout>
```

我们所做的是将网格块添加为我们的主块的一部分，但如果我们转到客户编辑页面并点击**礼品注册**选项卡，我们仍然看到旧的占位文本，并且网格没有显示。

![网格小部件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_05_02.jpg)

这是因为我们还没有对`main.phtml`模板文件进行必要的更改。为了显示子块，我们需要明确告诉模板系统加载任何或特定的子块；现在，我们将只加载我们特定的网格块。执行以下步骤：

1.  打开`main.phtml`模板文件，该文件位于`app/design/adminhtml/default/default/template/customer/`位置。

1.  用以下内容替换模板代码：

```php
<div class="entry-edit">
    <div class="entry-edit-head">
        <h4 class="icon-head head-customer-view"><?php echo $this->__('Customer Gift Registry List') ?></h4>
    </div>
    <?php echo $this->getChildHtml('tab_giftregistry_list'); ?>
</div>
```

`getChildHtml()`函数负责渲染所有子块。

`getChildHtml()`函数可以使用特定的子块名称或无参数调用；如果没有参数调用，它将加载所有可用的子块。

在我们的扩展情况下，我们只对实例化特定的子块感兴趣，所以我们将传递块名称作为函数参数。现在，如果我们刷新页面，我们应该看到我们的网格块加载了该特定客户的所有可用礼品注册。

## 管理注册表

现在，如果我们想要管理特定客户的注册表，这很方便，但如果我们想要管理商店中所有可用的注册表，这并不真正帮助我们。为此，我们需要创建一个加载所有可用礼品注册的网格。

由于我们已经为后端创建了礼品注册控制器，我们可以使用索引操作来显示所有可用的注册表。

我们需要做的第一件事是修改 Magento 后端导航，以显示指向我们新控制器索引操作的链接。同样，我们可以通过使用 XML 来实现这一点。在这种特殊情况下，我们将创建一个名为`adminhtml.xml`的新 XML 文件。执行以下步骤：

1.  导航到您的模块`etc`文件夹，该文件夹位于`app/code/local/Mdg/Giftregistry/`位置。

1.  创建一个名为`adminhtml.xml`的新文件。

1.  将以下代码放入该文件中：

```php
<?xml version="1.0"?>
<config>
    <menu>
        <mdg_giftregistry module="mdg_giftregistry">
            <title>Gift Registry</title>
            <sort_order>71</sort_order>
            <children>
                <items module="mdg_giftregistry">
                    <title>Manage Registries</title>
                    <sort_order>0</sort_order>
                    <action>adminhtml/giftregistry/index</action>
                </items>
            </children>
        </mdg_giftregistry>
    </menu>
</config>
```

### 注意

虽然标准是将此配置添加到`adminhtml.xml`中，但您可能会遇到未遵循此标准的扩展。此配置可以位于`config.xml`中。

这个配置代码正在创建一个新的主级菜单和一个新的子级选项；我们还指定了菜单应映射到哪个操作，在这种情况下，是我们的礼品注册控制器的索引操作。

如果我们现在刷新后端，我们应该会看到一个新的**礼品注册**菜单添加到顶级导航中。

## 权限和 ACL

有时我们需要根据管理员规则限制对模块的某些功能甚至整个模块的访问。Magento 允许我们使用一个称为**ACL**或**访问控制列表**的强大功能来实现这一点。Magento 后端中的每个角色都可以具有不同的权限和不同的 ACL。

启用我们自定义模块的 ACL 的第一步是定义 ACL 应该受限制的资源；这由配置 XML 文件控制，这并不奇怪。执行以下步骤：

1.  打开`adminhtml.xml`配置文件，该文件位于`app/code/local/Mdg/Giftregistry/etc/`位置。

1.  在菜单路径之后添加以下代码：

```php
<acl>
    <resources>
        <admin>
            <children>
                <giftregistry translate="title" module="mdg_giftregistry">
                    <title>Gift Registry</title>
                    <sort_order>300</sort_order>
                    <children>
                        <items translate="title" module="mdg_giftregistry">
                            <title>Manage Registries</title>
                            <sort_order>0</sort_order>
                        </items>
                    </children>
                </giftregistry>
            </children>
        </admin>
    </resources>
</acl>
```

现在，在 Magento 后端，如果我们导航到**系统** | **权限** | **角色**，选择**管理员**角色，并尝试在列表底部设置**角色资源**，我们可以看到我们创建的新 ACL 资源，如下面的截图所示：

![权限和 ACL](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_05_06.jpg)

通过这样做，我们可以精细控制每个用户可以访问哪些操作。

如果我们点击**管理注册表**菜单，我们应该会看到一个空白页面；因为我们还没有创建相应的网格块、布局和模板，所以我们应该会看到一个完全空白的页面。

所以让我们开始创建我们新网格所需的块；我们创建礼品注册表网格的方式将与我们为**客户**选项卡所做的略有不同。

我们需要创建一个网格容器块和一个网格块。网格容器用于保存网格标题、按钮和网格内容，而网格块只负责呈现带有分页、过滤和批量操作的网格。执行以下步骤：

1.  导航到您的块`Adminhtml`文件夹。

1.  在`app/code/local/Mdg/Giftregistry/Block/Adminhtml/`位置创建一个名为`Registries.php`的新块：

1.  将以下代码添加到其中：

```php
<?php
class Mdg_Giftregistry_Block_Adminhtml_Registries extends Mage_Adminhtml_Block_Widget_Grid_Container
{
public function __construct(){
    $this->_controller = 'adminhtml_registries';
    $this->_blockGroup = 'mdg_giftregistry';
    $this->_headerText = Mage::helper('mdg_giftregistry')->__('Gift Registry Manager');
    parent::__construct();
  }
}
```

我们在网格容器内的`construct`函数中设置的一个重要的事情是使用受保护的`_controller`和`_blockGroup`值，Magento 网格容器通过这些值来识别相应的网格块。

重要的是要澄清，`$this->_controller`不是实际的控制器名称，而是块类名称，`$this->_blockGroup`实际上是模块名称。

让我们继续创建网格块，正如我们之前学到的那样，它有三个主要功能：`_construct`，`_prepareCollection()`和`_prepareColumns()`。但在这种情况下，我们将添加一个名为`_prepareMassActions()`的新功能，它允许我们修改所选记录集而无需逐个编辑。执行以下步骤：

1.  导航到您的块`Adminhtml`文件夹并创建一个名为`Registries`的新文件夹。

1.  在`Model`文件夹下，在`app/code/local/Mdg/Giftregistry/Block/Adminhtml/Registries/`位置创建一个名为`Grid.php`的新块。

1.  将以下代码添加到`Grid.php`中：

```php
File Location: Grid.php
<?php
class Mdg_Giftregistry_Block_Adminhtml_Registries_Grid extends Mage_Adminhtml_Block_Widget_Grid
{
    public function __construct(){
        parent::__construct();
        $this->setId('registriesGrid');
        $this->setDefaultSort('event_date');
        $this->setDefaultDir('ASC');
        $this->setSaveParametersInSession(true);
    }

    protected function _prepareCollection(){
        $collection = Mage::getModel('mdg_giftregistry/entity')->getCollection();
        $this->setCollection($collection);
        return parent::_prepareCollection();
    }

    protected function _prepareColumns()
    {
        $this->addColumn('entity_id', array(
            'header'   => Mage::helper('mdg_giftregistry')->__('Id'),
            'width'    => 50,
            'index'    => 'entity_id',
            'sortable' => false,
        ));

        $this->addColumn('event_location', array(
            'header'   => Mage::helper('mdg_giftregistry')->__('Location'),
            'index'    => 'event_location',
            'sortable' => false,
        ));

        $this->addColumn('event_date', array(
            'header'   => Mage::helper('mdg_giftregistry')->__('Event Date'),
            'index'    => 'event_date',
            'sortable' => false,
        ));

        $this->addColumn('type_id', array(
            'header'   => Mage::helper('mdg_giftregistry')->__('Event Type'),
            'index'    => 'type_id',
            'sortable' => false,
        ));
        return parent::_prepareColumns();
    }

    protected function _prepareMassaction(){
    }
}
```

这个网格代码与我们之前为**客户**选项卡创建的非常相似，唯一的区别是这次我们不是特别按客户记录进行过滤，而且我们还创建了一个网格容器块，而不是实现一个自定义块。

最后，为了在我们的控制器动作中显示网格，我们需要执行以下步骤：

1.  打开`giftregistry.xml`文件，该文件位于`app/code/design/adminhtml/default/default/layout/`位置。

1.  将以下代码添加到其中：

```php
…
    <adminhtml_giftregistry_index>
         <reference name="content">
             <block type="mdg_giftregistry/adminhtml_registries" name="registries" />
         </reference>
     </adminhtml_giftregistry_index>
…
```

由于我们使用了网格容器，我们只需要指定网格容器块，Magento 将负责加载匹配的网格容器。

无需为网格或网格容器指定或创建模板文件，因为这两个块都会自动从`adminhtml/base/default`主题加载基本模板。

现在，我们可以通过在后端导航到**礼品注册** | **管理注册表**来检查我们新添加的礼品注册。

![权限和 ACL](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_05_03.jpg)

## 使用大规模操作进行批量更新

在创建我们的基本网格块时，我们定义了一个名为`_prepareMassactions()`的函数，它提供了一种简单的方式来操作网格中的多条记录。在我们的情况下，现在让我们只实现一个大规模删除动作。执行以下步骤：

1.  打开注册表格块`Grid.php`，该文件位于`app/code/local/Mdg/Giftregistry/Block/Adminhtml/Registries/`位置。

1.  用以下代码替换`_prepareMassaction()`函数：

```php
protected function _prepareMassaction(){
    $this->setMassactionIdField('entity_id');
    $this->getMassactionBlock()->setFormFieldName('registries');

    $this->getMassactionBlock()->addItem('delete', array(
        'label'     => Mage::helper('mdg_giftregistry')->__('Delete'),
        'url'       => $this->getUrl('*/*/massDelete'),
        'confirm'   => Mage::helper('mdg_giftregistry')->__('Are you sure?')
    ));
    return $this;
}
```

大规模操作的工作方式是通过将一系列选定的 ID 传递给我们指定的控制器动作；在这种情况下，`massDelete()`动作将添加代码来迭代注册表集合并删除每个指定的注册表。执行以下步骤：

1.  打开`GiftregistryController.php`文件，该文件位于`app/code/local/Mdg/Giftregistry/controllers/Adminhtml/`位置。

1.  用以下代码替换空白的`massDelete()`动作：

```php
…
public function massDeleteAction()
{
    $registryIds = $this->getRequest()->getParam('registries');
        if(!is_array($registryIds)) {
             Mage::getSingleton('adminhtml/session')->addError(Mage::helper('mdg_giftregistry')->__('Please select one or more registries.'));
        } else {
            try {
                $registry = Mage::getModel('mdg_giftregistry/entity');
                foreach ($registryIds as $registryId) {
                    $registry->reset()
                        ->load($registryId)
                        ->delete();
                }
                Mage::getSingleton('adminhtml/session')->addSuccess(
                Mage::helper('adminhtml')->__('Total of %d record(s) were deleted.', count($registryIds))
                );
            } catch (Exception $e) {
                Mage::getSingleton('adminhtml/session')->addError($e->getMessage());
            }
        }
        $this->_redirect('*/*/index');
}
```

### 注意

**挑战**：添加两个新的大规模操作，将注册表的状态分别更改为启用或禁用。要查看完整代码和详细分解的答案，请访问[`www.magedevguide.com/`](http://www.magedevguide.com/)。

最后，我们还希望能够编辑我们网格中列出的记录。为此，我们需要向我们的注册表格类添加一个新函数；这个函数被称为`getRowUrl()`，它用于指定单击网格行时要执行的操作；在我们的特定情况下，我们希望将该函数映射到`editAction()`。执行以下步骤：

1.  打开`Grid.php`文件，该文件位于`app/code/local/Mdg/Giftregistry/Block/Adminhtml/Registries/`位置。

1.  向其中添加以下函数：

```php
…
public function getRowUrl($row)
{
    return $this->getUrl('*/*/edit', array('id' => $row->getEntityId()));
}
…
```

# 表单小部件

到目前为止，我们一直在处理礼品注册表格，但现在我们除了获取所有可用注册表的列表或批量删除注册表之外，无法做更多事情。我们需要一种方法来获取特定注册表的详细信息；我们可以将其映射到编辑控制器动作。

`edit`动作将显示特定注册表的详细信息，并允许我们修改注册表的详细信息和状态。我们需要为此动作创建一些块和模板。

为了查看和编辑注册表信息，我们需要实现一个表单小部件块。表单小部件的工作方式与网格小部件块类似，需要有一个表单块和一个扩展`Mage_Adminhtml_Block_Widget_Form_Container`类的表单容器块。为了创建表单容器，让我们执行以下步骤：

1.  导航到`Registries`文件夹。

1.  在`app/code/local/Mdg/Giftregistry/Block/Adminhtml/Registries/`位置创建一个名为`Edit.php`的新类文件。

1.  向类文件中添加以下代码：

```php
class Mdg_Giftregistry_Block_Adminhtml_Registries_Edit extends Mage_Adminhtml_Block_Widget_Form_Container
{
    public function __construct(){
        parent::__construct();
        $this->_objectId = 'id';
        $this->_blockGroup = 'registries';
        $this->_controller = 'adminhtml_giftregistry';
        $this->_mode = 'edit';

        $this->_updateButton('save', 'label', Mage::helper('mdg_giftregistry')->__('Save Registry'));
        $this->_updateButton('delete', 'label', Mage::helper('mdg_giftregistry')->__('Delete Registry'));
    }

    public function getHeaderText(){
        if(Mage::registry('registries_data') && Mage::registry('registries_data')->getId())
            return Mage::helper('mdg_giftregistry')->__("Edit Registry '%s'", $this->htmlEscape(Mage::registry('registries_data')->getTitle()));
        return Mage::helper('mdg_giftregistry')->__('Add Registry');
    }
}
```

与网格小部件类似，表单容器小部件将自动识别并加载匹配的表单块。

在表单容器中声明的另一个受保护属性是 mode 属性；这个受保护属性被容器用来指定表单块的位置。

我们可以在`Mage_Adminhtml_Block_Widget_Form_Container`类中找到负责创建表单块的代码：

```php
$this->getLayout()->createBlock($this->_blockGroup . '/' . $this->_controller . '_' . $this->_mode . '_form')
```

现在我们已经创建了表单容器块，我们可以继续创建匹配的表单块。执行以下步骤：

1.  导航到`Registries`文件夹。

1.  创建一个名为`Edit`的新文件夹。

1.  在`app/code/local/Mdg/Giftregistry/Block/Adminhtml/Registries/Edit/`位置创建一个名为`Form.php`的新文件。

1.  向其中添加以下代码：

```php
<?php
class Mdg_Giftregistry_Block_Adminhtml_Registries_Edit_Form extends  Mage_Adminhtml_Block_Widget_Form
{
    protected function _prepareForm(){
        $form = new Varien_Data_Form(array(
            'id' => 'edit_form',
            'action' => $this->getUrl('*/*/save', array('id' => $this->getRequest()->getParam('id'))),
            'method' => 'post',
            'enctype' => 'multipart/form-data'
        ));
        $form->setUseContainer(true);
        $this->setForm($form);

        if (Mage::getSingleton('adminhtml/session')->getFormData()){
            $data = Mage::getSingleton('adminhtml/session')->getFormData();
            Mage::getSingleton('adminhtml/session')->setFormData(null);
        }elseif(Mage::registry('registry_data'))
            $data = Mage::registry('registry_data')->getData();

        $fieldset = $form->addFieldset('registry_form', array('legend'=>Mage::helper('mdg_giftregistry')->__('Gift Registry information')));

        $fieldset->addField('type_id', 'text', array(
            'label'     => Mage::helper('mdg_giftregistry')->__('Registry Id'),
            'class'     => 'required-entry',
            'required'  => true,
            'name'      => 'type_id',
        ));

        $fieldset->addField('website_id', 'text', array(
            'label'     => Mage::helper('mdg_giftregistry')->__('Website Id'),
            'class'     => 'required-entry',
            'required'  => true,
            'name'      => 'website_id',
        ));

        $fieldset->addField('event_location', 'text', array(
            'label'     => Mage::helper('mdg_giftregistry')->__('Event Location'),
            'class'     => 'required-entry',
            'required'  => true,
            'name'      => 'event_location',
        ));

        $fieldset->addField('event_date', 'text', array(
            'label'     => Mage::helper('mdg_giftregistry')->__('Event Date'),
            'class'     => 'required-entry',
            'required'  => true,
            'name'      => 'event_date',
        ));

        $fieldset->addField('event_country', 'text', array(
            'label'     => Mage::helper('mdg_giftregistry')->__('Event Country'),
            'class'     => 'required-entry',
            'required'  => true,
            'name'      => 'event_country',
        ));

        $form->setValues($data);
        return parent::_prepareForm();
    }
}
```

我们还需要修改我们的布局文件，并告诉 Magento 加载我们的表单容器。

将以下代码复制到布局文件`giftregistry.xml`中，该文件位于`app/code/design/adminhtml/default/default/layout/`位置：

```php
<?xml version="1.0"?>
<layout version="0.1.0">
    …
    <adminhtml_giftregistry_edit>
        <reference name="content">
            <block type="mdg_giftregistry/adminhtml_registries_edit" name="new_registry_tabs" />
        </reference>
    </adminhtml_giftregistry_edit>
    …
```

此时，我们可以进入 Magento 后端，点击我们的示例注册表之一，查看我们的进展。我们应该看到以下表单：

![表单小部件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_05_04.jpg)

但似乎有一个问题。没有加载任何数据；我们只有一个空表单，因此我们必须修改我们的控制器`editAction()`以加载数据。

## 加载数据

让我们从修改`GiftregistryController.php`文件中的`editAction()`开始，该文件位于`app/code/local/Mdg/Giftregistry/controllers/Adminhtml/`位置：

```php
…
public function editAction()
{
    $id     = $this->getRequest()->getParam('id', null);
    $registry  = Mage::getModel('mdg_giftregistry/entity');

    if ($id) {
        $registry->load((int) $id);
        if ($registry->getId()) {
            $data = Mage::getSingleton('adminhtml/session')->getFormData(true);
            if ($data) {
                $registry->setData($data)->setId($id);
            }
        } else {
            Mage::getSingleton('adminhtml/session')->addError(Mage::helper('awesome')->__('The Gift Registry does not exist'));
            $this->_redirect('*/*/');
        }
    }
    Mage::register('registry_data', $registry);

    $this->loadLayout();
    $this->getLayout()->getBlock('head')->setCanLoadExtJs(true);
    $this->renderLayout();
}
```

我们在`editAction()`中所做的是检查是否存在具有相同 ID 的注册表，如果存在，我们将加载该注册表实体并使其可用于我们的表单。之前，在将表单代码添加到文件`app/code/local/Mdg/Giftregistry/Block/Adminhtml/Registries/Edit/Form.php`时，我们包括了以下内容：

```php
…
if (Mage::getSingleton('adminhtml/session')->getFormData()){
    $data = Mage::getSingleton('adminhtml/session')->getFormData();
    Mage::getSingleton('adminhtml/session')->setFormData(null);
}elseif(Mage::registry('registry_data'))
    $data = Mage::registry('registry_data')->getData();  
…
```

现在，我们可以通过重新加载表单来测试我们的更改：

![加载数据](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_05_05.jpg)

## 保存数据

现在我们已经为编辑注册表创建了表单，我们需要创建相应的操作来处理并保存表单提交的数据。我们可以使用保存表单操作来处理这个过程。执行以下步骤：

1.  打开`GiftregistryController.php`类，该类位于`app/code/local/Mdg/Giftregistry/controllers/Adminhtml/`位置。

1.  用以下代码替换空白的`saveAction()`函数：

```php
public function saveAction()
{
    if ($this->getRequest()->getPost())
    {
        try {
            $data = $this->getRequest()->getPost();
            $id = $this->getRequest()->getParam('id');

            if ($data && $id) {
                $registry = Mage::getModel('mdg_giftregistry/entity')->load($id);
                $registry->setData($data);
                $registry->save();
                  $this->_redirect('*/*/edit', array('id' => $this->getRequest()->getParam('registry_id')));
            }
        } catch (Exception $e) {
            $this->_getSession()->addError(
                Mage::helper('mdg_giftregistry')->__('An error occurred while saving the registry data. Please review the log and try again.')
            );
            Mage::logException($e);
            $this->_redirect('*/*/edit', array('id' => $this->getRequest()->getParam('registry_id')));
            return $this;
        }
    }
}
```

让我们逐步分解一下这段代码在做什么：

1.  我们检查请求是否具有有效的提交数据。

1.  我们检查`$data`和`$id`变量是否都设置了。

1.  如果两个变量都设置了，我们加载一个新的注册表实体并设置数据。

1.  最后，我们尝试保存注册表实体。

我们首先要做的是检查提交的数据不为空，并且我们在参数中获取了注册表 ID；我们还检查注册表 ID 是否是注册表实体的有效实例。

# 总结

在本章中，我们学会了如何修改和扩展 Magento 后端以满足我们的特定需求。

前端扩展了客户和用户可以使用的功能；扩展后端允许我们控制这个自定义功能以及客户与其交互的方式。

网格和表单是 Magento 后端的重要部分，通过正确使用它们，我们可以添加很多功能，而不必编写大量代码或重新发明轮子。

最后，我们学会了如何使用权限和 Magento ACL 来控制和限制我们的自定义扩展以及 Magento 的权限。

在下一章中，我们将深入研究 Magento API，并学习如何扩展它以使用多种方法（如 SOAP、XML-RPC 和 REST）来操作我们的注册表数据。
