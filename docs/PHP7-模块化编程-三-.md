# PHP7 模块化编程（三）

> 原文：[`zh.annas-archive.org/md5/ff0acc039cf922de0886cd9283ec3d9f`](https://zh.annas-archive.org/md5/ff0acc039cf922de0886cd9283ec3d9f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：构建目录模块

目录模块是每个网店应用程序的基本组成部分。在最基本的级别上，它负责管理和显示类别和产品。这是以后模块的基础，例如结账，它为我们的网店应用程序添加了实际的销售功能。

更强大的目录功能可能包括大规模产品导入、产品导出、多仓库库存管理、私人会员类别等。然而，这些超出了本章的范围。

在本章中，我们将涵盖以下主题：

+   要求

+   依赖关系

+   实现

+   单元测试

+   功能测试

# 要求

根据第四章中定义的高级应用程序要求，*模块化网店应用的需求规范*，我们的模块将实现多个实体和其他特定功能。

以下是所需模块实体的列表：

+   类别

+   产品

类别实体包括以下属性及其数据类型：

+   `id`：整数，自增

+   `title`：字符串

+   `url_key`：字符串，唯一

+   `description`：文本

+   `image`：字符串

产品实体包括以下属性：

+   `id`：整数，自增

+   `category_id`：整数，引用类别表 ID 列的外键

+   `title`：字符串

+   `price`：十进制

+   `sku`：字符串，唯一

+   `url_key`：字符串，唯一

+   `description`：文本

+   `qty`：整数

+   `image`：字符串

+   `onsale`：布尔值

除了添加这些实体及其 CRUD 页面之外，我们还需要覆盖负责构建类别菜单和特价商品的核心模块服务。

# 依赖关系

该模块对任何其他模块没有明确的依赖关系。Symfony 框架服务层使我们能够以这样的方式编写模块，大多数情况下它们之间不需要依赖关系。虽然该模块确实覆盖了核心模块中定义的一个服务，但该模块本身并不依赖于它，如果覆盖的服务丢失，也不会出现任何问题。

# 实现

我们首先创建一个名为`Foggyline\CatalogBundle`的新模块。我们通过控制台运行以下命令来完成：

```php
**php bin/console generate:bundle --namespace=Foggyline/CatalogBundle**

```

该命令触发一个交互过程，在这个过程中，会向我们询问几个问题，如下截图所示：

![实现](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_07_01.jpg)

完成后，我们生成了以下结构：

![实现](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_07_03.jpg)

如果我们现在查看`app/AppKernel.php`文件，我们会在`registerBundles`方法下看到以下行：

```php
new Foggyline\CatalogBundle\FoggylineCatalogBundle()
```

同样，`app/config/routing.yml`中添加了以下路由定义：

```php
foggyline_catalog:
  resource: "@FoggylineCatalogBundle/Resources/config/routing.xml"
  prefix: /
```

在这里，我们需要将`prefix: /`更改为`prefix: /catalog/`，以便不与核心模块路由冲突。保持`prefix: /`将简单地覆盖我们的核心`AppBundle`，并从`src/Foggyline/CatalogBundle/Resources/views/Default/index.html.twig`模板向浏览器输出`Hello World!`。我们希望保持事情的清晰分离。这意味着该模块不为自身定义根路由。

## 创建实体

让我们继续创建一个`Category`实体。我们通过控制台来完成，如下所示：

```php
**php bin/console generate:doctrine:entity**

```

![创建实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_07_04.jpg)

这将在`src/Foggyline/CatalogBundle/`目录中创建`Entity/Category.php`和`Repository/CategoryRepository.php`文件。之后，我们需要更新数据库，以便引入`Category`实体，如下命令行示例所示：

```php
**php bin/console doctrine:schema:update --force**

```

这将产生一个类似于以下截图的屏幕：

![创建实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_07_05.jpg)

有了实体，我们就可以生成其 CRUD。我们通过以下命令来完成：

```php
**php bin/console generate:doctrine:crud**

```

这将产生如下交互式输出：

![创建实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_07_06.jpg)

这导致创建了`src/Foggyline/CatalogBundle/Controller/CategoryController.php`。它还在我们的`app/config/routing.yml`文件中添加了一个条目，如下所示：

```php
foggyline_catalog_category:
  resource: "@FoggylineCatalogBundle/Controller/CategoryController.php"
  type:     annotation
```

此外，视图文件创建在`app/Resources/views/category/`目录下，这不是我们所期望的。我们希望它们在我们的模块`src/Foggyline/CatalogBundle/Resources/views/Default/category/`目录下，因此我们需要将它们复制过去。此外，我们需要修改`CategoryController`中的所有`$this->render`调用，通过在每个模板路径后附加`FoggylineCatalogBundle:default: string`来修改它们。

接下来，我们继续使用之前讨论过的交互式生成器创建`Product`实体：

```php
**php bin/console generate:doctrine:entity**

```

我们遵循交互式生成器，尊重以下属性的最小值：`title`、`price`、`sku`、`url_key`、`description`、`qty`、`category`和`image`。除了`price`和`qty`是十进制和整数类型之外，所有其他属性都是字符串类型。此外，`sku`和`url_key`被标记为唯一。这将在`src/Foggyline/CatalogBundle/`目录中创建`Entity/Product.php`和`Repository/ProductRepository.php`文件。

与我们为`Category view`模板所做的类似，我们需要为`Product view`模板做同样的事情。也就是说，将它们从`app/Resources/views/product/`目录复制到`src/Foggyline/CatalogBundle/Resources/views/Default/product/`，并通过在每个模板路径后附加`FoggylineCatalogBundle:default: string`来更新`ProductController`中的所有`$this->render`调用。

此时，我们不会急于更新模式，因为我们想要为我们的代码添加适当的关系。每个产品应该能够与单个`Category`实体建立关系。为了实现这一点，我们需要编辑`src/Foggyline/CatalogBundle/Entity/`目录中的`Category.php`和`Product.php`，如下所示：

```php
// src/Foggyline/CatalogBundle/Entity/Category.php

/**
 * @ORM\OneToMany(targetEntity="Product", mappedBy="category")
 */
private $products;

public function __construct()
{
  $this->products = new \Doctrine\Common\Collections\ArrayCollection();
}

// src/Foggyline/CatalogBundle/Entity/Product.php

/**
 * @ORM\ManyToOne(targetEntity="Category", inversedBy="products")
 * @ORM\JoinColumn(name="category_id", referencedColumnName="id")
 */
private $category;
```

我们还需要编辑`Category.php`文件，添加`__toString`方法的实现，如下所示：

```php
public function __toString()
{
    return $this->getTitle();
}
```

我们这样做的原因是，稍后，我们的产品编辑表单将知道在类别选择下列出什么标签，否则系统会抛出以下错误：

```php
Catchable Fatal Error: Object of class Foggyline\CatalogBundle\Entity\Category could not be converted to string
```

有了以上更改，我们现在可以运行模式更新，如下所示：

```php
**php bin/console doctrine:schema:update --force**

```

如果我们现在查看我们的数据库，`product`表的`CREATE`命令语法如下所示：

```php
CREATE TABLE `product` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `category_id` int(11) DEFAULT NULL,
  `title` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `sku` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `url_key` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `description` longtext COLLATE utf8_unicode_ci,
  `qty` int(11) NOT NULL,
  `image` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UNIQ_D34A04ADF9038C4` (`sku`),
  UNIQUE KEY `UNIQ_D34A04ADDFAB7B3B` (`url_key`),
  KEY `IDX_D34A04AD12469DE2` (`category_id`),
  CONSTRAINT `FK_D34A04AD12469DE2` FOREIGN KEY (`category_id`) REFERENCES `category` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
```

我们可以看到定义了两个唯一键和一个外键约束，根据我们交互式实体生成器提供的条目。现在我们准备为我们的`Product`实体生成 CRUD。为此，我们运行`generate:doctrine:crud`命令，并按照交互式生成器的指示进行操作，如下所示：

![创建实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_07_07.jpg)

## 管理图像上传

此时，如果我们访问`/category/new/`或`/product/new/`URL，图像字段只是一个简单的文本输入字段，而不是我们想要的实际图像上传。为了将其变成图像上传字段，我们需要编辑`Category.php`和`Product.php`中的`$image`属性，如下所示：

```php
//…
use Symfony\Component\Validator\Constraints as Assert;
//…
class [Category|Product]
{
  //…
  /**
  * @var string
  *
  * @ORM\Column(name="image", type="string", length=255, nullable=true)
  * @Assert\File(mimeTypes={ "image/png", "image/jpeg" }, mimeTypesMessage="Please upload the PNG or JPEG image file.")
  */
  private $image;
  //…
}
```

一旦我们这样做，输入字段就变成了文件上传字段，如下所示：

![管理图像上传](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_07_09.jpg)

接下来，我们将继续将上传功能实现到表单中。

我们首先通过在`src/Foggyline/CatalogBundle/Resources/config/services.xml`文件的`services`元素下添加以下条目来定义处理实际上传的服务：

```php
<service id="foggyline_catalog.image_uploader" class="Foggyline\CatalogBundle\Service\ImageUploader">
  <argument>%foggyline_catalog_images_directory%</argument>
</service>
```

`%foggyline_catalog_images_directory%`参数值是我们即将定义的一个参数的名称。

然后，我们创建`src/Foggyline/CatalogBundle/Service/ImageUploader.php`文件，内容如下：

```php
namespace Foggyline\CatalogBundle\Service;

use Symfony\Component\HttpFoundation\File\UploadedFile;

class ImageUploader
{
  private $targetDir;

  public function __construct($targetDir)
  {
    $this->targetDir = $targetDir;
  }

  public function upload(UploadedFile $file)
  {
    $fileName = md5(uniqid()) . '.' . $file->guessExtension();
    $file->move($this->targetDir, $fileName);
    return $fileName;
  }
}
```

然后，我们在`src/Foggyline/CatalogBundle/Resources/config`目录中创建自己的`parameters.yml`文件，内容如下：

```php
parameters:
  foggyline_catalog_images_directory: "%kernel.root_dir%/../web/uploads/foggyline_catalog_images"
```

这是我们的服务期望找到的参数。如果需要，可以在`app/config/parameters.yml`下用相同的条目轻松覆盖它。

为了使我们的 bundle 能够看到`parameters.yml`文件，我们仍然需要编辑`src/Foggyline/CatalogBundle/DependencyInjection/ directory`中的`FoggylineCatalogExtension.php`文件，通过在`load`方法的末尾添加以下`loader`来实现：

```php
$loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
$loader->load('parameters.yml');
```

此时，我们的 Symfony 模块能够读取其`parameters.yml`，从而使其定义的服务能够获取其参数的正确值。现在只需要调整我们的`new`和`edit`表单的代码，将上传功能附加到它们上。由于这两个表单是相同的，以下是一个同样适用于`Product`表单的`Category`示例：

```php
public function newAction(Request $request) {
  // ...

  if ($form->isSubmitted() && $form->isValid()) {
    /* @var $image \Symfony\Component\HttpFoundation\File\UploadedFile */
    if ($image = $category->getImage()) {
      $name = $this->get('foggyline_catalog.image_uploader')->upload($image);
      $category->setImage($name);
    }

    $em = $this->getDoctrine()->getManager();
    // ...
  }

  // ...
}

public function editAction(Request $request, Category $category) {
  $existingImage = $category->getImage();
  if ($existingImage) {
    $category->setImage(
      new File($this->getParameter('foggyline_catalog_images_directory') . '/' . $existingImage)
    );
  }

  $deleteForm = $this->createDeleteForm($category);
  // ...

  if ($editForm->isSubmitted() && $editForm->isValid()) {
    /* @var $image \Symfony\Component\HttpFoundation\File\UploadedFile */
    if ($image = $category->getImage()) {
      $name = $this->get('foggyline_catalog.image_uploader')->upload($image);
      $category->setImage($name);
    } elseif ($existingImage) {
      $category->setImage($existingImage);
    }

    $em = $this->getDoctrine()->getManager();
    // ...
  }

  // ...
}
```

现在`new`和`edit`表单都应该能够处理文件上传。

## 覆盖核心模块服务

现在让我们继续处理类别菜单和特价商品。在构建核心模块时，我们在`app/config/config.yml`文件的`twig:global`部分定义了全局变量。这些变量指向了在`app/config/services.yml`文件中定义的服务。为了改变类别菜单和特价商品的内容，我们需要覆盖这些服务。

我们首先在`src/Foggyline/CatalogBundle/Resources/config/services.xml`文件中添加以下两个服务定义：

```php
<service id="foggyline_catalog.category_menu" class="Foggyline\CatalogBundle\Service\Menu\Category">
  <argument type="service" id="doctrine.orm.entity_manager" />
  <argument type="service" id="router" />
</service>

<service id="foggyline_catalog.onsale" class="Foggyline\CatalogBundle\Service\Menu\OnSale">
  <argument type="service" id="doctrine.orm.entity_manager" />
  <argument type="service" id="router" />
</service>
```

这两个服务都接受 Doctrine ORM 实体管理器和路由器服务参数，因为我们需要在内部使用它们。

然后我们在`src/Foggyline/CatalogBundle/Service/Menu/`目录中创建了实际的`Category`和`OnSale`服务类，如下所示：

```php
//Category.php

namespace Foggyline\CatalogBundle\Service\Menu;

class Category
{
  private $em;
  private $router;

  public function __construct(
    \Doctrine\ORM\EntityManager $entityManager,
    \Symfony\Bundle\FrameworkBundle\Routing\Router $router
  )
  {
    $this->em = $entityManager;
    $this->router = $router;
  }

  public function getItems()
  {
    $categories = array();
    $_categories = $this->em->getRepository('FoggylineCatalogBundle:Category')->findAll();

    foreach ($_categories as $_category) {
      /* @var $_category \Foggyline\CatalogBundle\Entity\Category */
      $categories[] = array(
        'path' => $this->router->generate('category_show', array('id' => $_category->getId())),
        'label' => $_category->getTitle(),
      );
    }

    return $categories;
  }
}
 //OnSale.php

namespace Foggyline\CatalogBundle\Service\Menu;

class OnSale
{
  private $em;
  private $router;

  public function __construct(\Doctrine\ORM\EntityManager $entityManager, $router)
  {
    $this->em = $entityManager;
    $this->router = $router;
  }

  public function getItems()
  {
    $products = array();
    $_products = $this->em->getRepository('FoggylineCatalogBundle:Product')->findBy(
        array('onsale' => true),
        null,
        5
    );

    foreach ($_products as $_product) {
      /* @var $_product \Foggyline\CatalogBundle\Entity\Product */
      $products[] = array(
        'path' => $this->router->generate('product_show', array('id' => $_product->getId())),
        'name' => $_product->getTitle(),
        'image' => $_product->getImage(),
        'price' => $_product->getPrice(),
        'id' => $_product->getId(),
      );
    }

    return $products;
  }
}
```

这样单独做不会触发核心模块服务的覆盖。在`src/Foggyline/CatalogBundle/DependencyInjection/Compiler/`目录中，我们需要创建一个实现`CompilerPassInterface`的`OverrideServiceCompilerPass`类。在其`process`方法中，我们可以改变服务的定义，如下所示：

```php
namespace Foggyline\CatalogBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class OverrideServiceCompilerPass implements CompilerPassInterface
{
  public function process(ContainerBuilder $container)
  {
    // Override the core module 'category_menu' service
    $container->removeDefinition('category_menu');
    $container->setDefinition('category_menu', $container->getDefinition('foggyline_catalog.category_menu'));

    // Override the core module 'onsale' service
    $container->removeDefinition('onsale');
    $container->setDefinition('onsale', $container->getDefinition('foggyline_catalog.onsale'));
  }
}
```

最后，我们需要编辑`src/Foggyline/CatalogBundle/FoggylineCatalogBundle.php`文件的`build`方法，以添加这个编译器通行证，如下所示：

```php
public function build(ContainerBuilder $container)
{
  parent::build($container);
  $container->addCompilerPass(new \Foggyline\CatalogBundle\DependencyInjection\Compiler\OverrideServiceCompilerPass());
}
```

现在我们的`Category`和`OnSale`服务应该覆盖核心模块中定义的服务，从而为主页的标题**类别**菜单和**特价**部分提供正确的值。

## 设置类别页面

自动生成的 CRUD 为我们创建了一个类别页面，布局如下：

![设置类别页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_07_10.jpg)

这与第四章中定义的类别页面有很大不同，因此我们需要修改`src/Foggyline/CatalogBundle/Resources/views/Default/category/`目录中的`show.html.twig`文件来修改我们的类别展示页面。我们通过用以下代码替换`body`块的整个内容来实现：

```php
<div class="row">
  <div class="small-12 large-12 columns text-center">
    <h1>{{ category.title }}</h1>
    <p>{{ category.description }}</p>
  </div>
</div>

<div class="row">
  <img src="{{ asset('uploads/foggyline_catalog_images/' ~ category.image) }}"/>
</div>

{% set products = category.getProducts() %}
{% if products %}
<div class="row products_onsale text-center small-up-1 medium-up-3 large-up-5" data-equalizer data-equalize-by-row="true">
{% for product in products %}
<div class="column product">
  <img src="{{ asset('uploads/foggyline_catalog_images/' ~ product.image) }}" 
    alt="missing image"/>
  <a href="{{ path('product_show', {'id': product.id}) }}">{{ product.title }}</a>

  <div>${{ product.price }}</div>
  <div><a class="small button" href="{{ path('product_show', {'id': product.id}) }}">View</a></div>
  </div>
  {% endfor %}
</div>
{% else %}
<div class="row">
  <p>There are no products assigned to this category.</p>
</div>
{% endif %}

{% if is_granted('ROLE_ADMIN') %}
<ul>
  <li>
    <a href="{{ path('category_edit', { 'id': category.id }) }}">Edit</a>
  </li>
  <li>
    {{ form_start(delete_form) }}
    <input type="submit" value="Delete">
    form_end(delete_form) }}
  </li>
</ul>
{% endif %}
```

现在主体分为三个区域。首先，我们处理类别标题和描述输出。然后，我们获取并循环遍历分配给类别的产品列表，渲染每个单独的产品。最后，我们使用`is_granted` Twig 扩展来检查当前用户角色是否为`ROLE_ADMIN`，在这种情况下，我们显示类别的`编辑`和`删除`链接。

## 设置产品页面

自动生成的 CRUD 为我们创建了一个产品页面，布局如下：

![设置产品页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_07_11.jpg)

这与第四章中定义的产品页面有所不同，*模块化网店应用的需求规格*。为了纠正问题，我们需要修改`src/Foggyline/CatalogBundle/Resources/views/Default/product/`目录中的`show.html.twig`文件，通过替换`body`块的整个内容来实现。

```php
<div class="row">
  <div class="small-12 large-6 columns">
    <img class="thumbnail" src="{{ asset('uploads/foggyline_catalog_images/' ~ product.image) }}"/>
  </div>
  <div class="small-12 large-6 columns">
    <h1>{{ product.title }}</h1>
    <div>SKU: {{ product.sku }}</div>
    {% if product.qty %}
    <div>IN STOCK</div>
    {% else %}
    <div>OUT OF STOCK</div>
    {% endif %}
    <div>$ {{ product.price }}</div>
    <form action="{{ add_to_cart_url.getAddToCartUrl
      (product.id) }}" method="get">
      <div class="input-group">
        <span class="input-group-label">Qty</span>
        <input class="input-group-field" type="number">
        <div class="input-group-button">
          <input type="submit" class="button" value="Add to Cart">
        </div>
      </div>
    </form>
  </div>
</div>

<div class="row">
  <p>{{ product.description }}</p>
</div>

{% if is_granted('ROLE_ADMIN') %}
<ul>
  <li>
    <a href="{{ path('product_edit', { 'id': product.id }) }}">Edit</a>
  </li>
  <li>
    {{ form_start(delete_form) }}
    <input type="submit" value="Delete">
    {{ form_end(delete_form) }}
  </li>
</ul>
{% endif %}
```

现在，主体分为两个主要部分。首先，我们处理产品图片、标题、库存状态和添加到购物车输出。添加到购物车表单使用`add_to_cart_url`服务来提供正确的链接。这个服务在核心模块中定义，并且目前只提供一个虚拟链接。稍后，当我们到达结账模块时，我们将为这个服务实现一个覆盖，并注入正确的添加到购物车链接。然后我们输出描述部分。最后，我们使用`is_granted` Twig 扩展，就像我们在 Category 示例中所做的那样，来确定用户是否可以访问产品的`编辑`和`删除`链接。

# 单元测试

现在我们有几个与控制器无关的类文件，这意味着我们可以对它们进行单元测试。但是，作为本书的一部分，我们不会追求完整的代码覆盖率，而是专注于一些小而重要的事情，比如在我们的测试类中使用容器。

我们首先在`phpunit.xml.dist`文件的`testsuites`元素下添加以下行：

```php
<directory>src/Foggyline/CatalogBundle/Tests</directory>
```

有了这个设置，从我们商店的根目录运行`phpunit`命令应该会捡起我们在`src/Foggyline/CatalogBundle/Tests/`目录下定义的任何测试。

现在让我们为我们的 Category 服务菜单创建一个测试。我们通过创建一个`src/Foggyline/CatalogBundle/Tests/Service/Menu/CategoryTest.php`文件来实现：

```php
namespace Foggyline\CatalogBundle\Tests\Service\Menu;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Foggyline\CatalogBundle\Service\Menu\Category;

class CategoryTest extends KernelTestCase
{
  private $container;
  private $em;
  private $router;

  public function setUp()
  {
    static::bootKernel();
    $this->container = static::$kernel->getContainer();
    $this->em = $this->container->get('doctrine.orm.entity_manager');
    $this->router = $this->container->get('router');
  }

  public function testGetItems()
  {
    $service = new Category($this->em, $this->router);
    $this->assertNotEmpty($service->getItems());
  }

  protected function tearDown()
  {
    $this->em->close();
    unset($this->em, $this->router);
  }
}
```

前面的例子展示了`setUp`和`tearDown`方法的使用，它们的行为类似于 PHP 的`__construct`和`__destruct`方法。我们使用`setUp`方法来设置实体管理器和路由器服务，以便在类的其余部分中使用。`tearDown`方法只是一个清理工作。现在如果我们运行`phpunit`命令，我们应该能看到我们的测试被捡起并在其他测试之后执行。

我们甚至可以通过执行带有完整类路径的`phpunit`命令来专门针对这个类，如下所示：

```php
**phpunit src/Foggyline/CatalogBundle/Tests/Service/Menu/CategoryTest.php**

```

类似于我们为`CategoryTest`所做的，我们可以继续创建`OnSaleTest`；两者之间唯一的区别是类名。

# 功能测试

自动生成 CRUD 工具的好处在于它甚至为我们生成了功能测试。具体来说，在这种情况下，它在`src/Foggyline/CatalogBundle/Tests/Controller/`目录下生成了`CategoryControllerTest.php`和`ProductControllerTest.php`文件。

### 提示

自动生成的功能测试在类体内有注释掉的方法。这在`phpunit`运行时会报错。我们至少需要在其中定义一个虚拟的`test`方法，以便让`phpunit`忽略它们。

如果我们查看这两个文件，我们会发现它们都定义了一个`testCompleteScenario`方法，但是这个方法完全被注释掉了。让我们继续并修改`CategoryControllerTest.php`的内容如下：

```php
// Create a new client to browse the application
$client = static::createClient(
  array(), array(
    'PHP_AUTH_USER' => 'john',
    'PHP_AUTH_PW' => '1L6lllW9zXg0',
  )
);

// Create a new entry in the database
$crawler = $client->request('GET', '/category/');
$this->assertEquals(200, $client->getResponse()->getStatusCode(), "Unexpected HTTP status code for GET /product/");
$crawler = $client->click($crawler->selectLink('Create a new entry')->link());

// Fill in the form and submit it
$form = $crawler->selectButton('Create')->form(array(
  'category[title]' => 'Test',
  'category[urlKey]' => 'Test urlKey',
  'category[description]' => 'Test description',
));

$client->submit($form);
$crawler = $client->followRedirect();

// Check data in the show view
$this->assertGreaterThan(0, $crawler->filter('h1:contains("Test")')->count(), 'Missing element h1:contains("Test")');

// Edit the entity
$crawler = $client->click($crawler->selectLink('Edit')->link());

$form = $crawler->selectButton('Edit')->form(array(
  'category[title]' => 'Foo',
  'category[urlKey]' => 'Foo urlKey',
  'category[description]' => 'Foo description',
));

$client->submit($form);
$crawler = $client->followRedirect();

// Check the element contains an attribute with value equals "Foo"
$this->assertGreaterThan(0, $crawler->filter('[value="Foo"]')->count(), 'Missing element [value="Foo"]');

// Delete the entity
$client->submit($crawler->selectButton('Delete')->form());
$crawler = $client->followRedirect();

// Check the entity has been delete on the list
$this->assertNotRegExp('/Foo title/', $client->getResponse()->getContent());
```

我们首先将`PHP_AUTH_USER`和`PHP_AUTH_PW`设置为`createClient`方法的参数。这是因为我们的`/new`和`/edit`路由受核心模块安全保护。这些设置允许我们在请求中传递基本的 HTTP 身份验证。然后我们测试了类别列表页面是否可以访问以及它的`创建新条目`链接是否可以被点击。此外，我们还测试了`create`和`edit`表单以及它们的结果。

现在剩下的就是重复我们刚才在`CategoryControllerTest.php`中使用的方法，在`ProductControllerTest.php`中进行。我们只需要在`ProductControllerTest`类文件中更改一些标签，以匹配`product`路由和预期结果。

现在运行`phpunit`命令应该能成功执行我们的测试。

# 总结

在本章中，我们构建了一个微型但功能齐全的目录模块。它允许我们创建、编辑和删除类别和产品。通过在自动生成的 CRUD 之上添加几行自定义代码，我们能够为类别和产品实现图像上传功能。我们还看到了如何覆盖核心模块服务，只需删除现有的服务定义并提供一个新的定义。在测试方面，我们看到了如何在我们的请求中传递身份验证以测试受保护的路由。

在接下来的章节中，我们将构建一个客户模块。


# 第八章：构建客户模块

客户模块为我们的网店提供了进一步销售功能的基础。在非常基本的层面上，它负责注册、登录、管理和显示相关客户信息。这是后续销售模块的要求，它为我们的网店应用程序添加了实际的销售功能。

在本章中，我们将涵盖以下主题：

+   要求

+   依赖关系

+   实现

+   单元测试

+   功能测试

# 要求

根据第四章中定义的高级应用程序要求，*模块化网店应用的需求规范*，我们的模块将定义一个名为`Customer`的实体。

`Customer`实体包括以下属性：

+   `id`: integer, auto-increment

+   `email`: string, unique

+   `username`: string, unique, needed for login system

+   `password`: string

+   `first_name`: string

+   `last_name`: string

+   `company`: string

+   `phone_number`: string

+   `country`: string

+   `state`: string

+   `city`: string

+   `postcode`: string

+   `street`: string

在本章中，除了添加`Customer`实体及其 CRUD 页面之外，我们还需要处理登录、注册、忘记密码页面的创建，以及覆盖一个负责构建客户菜单的核心模块服务。

# 依赖关系

该模块不依赖于任何其他模块。虽然它覆盖了核心模块中定义的一个服务，但模块本身并不依赖于它。此外，一些安全配置将作为核心应用程序的一部分提供，我们稍后会看到。

# 实现

我们首先创建一个名为`Foggyline\CustomerBundle`的新模块。我们可以通过控制台运行以下命令来实现：

```php
**php bin/console generate:bundle --namespace=Foggyline/CustomerBundle**

```

该命令触发了一个交互式过程，在这个过程中会问我们一些问题，如下面的截图所示：

![实现](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_08_01.jpg)

完成后，我们得到了以下结构：

![实现](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_08_02.jpg)

如果我们现在查看`app/AppKernel.php`文件，我们会在`registerBundles`方法下看到以下行：

```php
new Foggyline\CustomerBundle\FoggylineCustomerBundle()
```

同样，`app/config/routing.yml`目录中添加了以下路由定义：

```php
foggyline_customer:
  resource: "@FoggylineCustomerBundle/Resources/config/routing.xml"
  prefix:   /
```

在这里，我们需要将`prefix: /`更改为`prefix: /customer/`，这样我们就不会与核心模块的路由冲突。保持`prefix: /`不变将简单地覆盖我们的核心`AppBundle`，并从`src/Foggyline/CustomerBundle/Resources/views/Default/index.html.twig`模板向浏览器输出**Hello World!**。我们希望保持事情的清晰和分离。这意味着该模块不为自己定义`root`路由。

## 创建客户实体

让我们继续创建一个`Customer`实体。我们可以通过控制台来实现：

```php
**php bin/console generate:doctrine:entity**

```

这个命令触发了交互式生成器，我们需要提供实体属性。完成后，生成器将在`src/Foggyline/CustomerBundle/`目录中创建`Entity/Customer.php`和`Repository/CustomerRepository.php`文件。之后，我们需要更新数据库，以便通过运行以下命令引入`Customer`实体：

```php
**php bin/console doctrine:schema:update --force**

```

这导致了一个屏幕，如下面的截图所示：

![创建客户实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_08_07.jpg)

有了实体，我们就可以生成它的 CRUD。我们可以通过以下命令来实现：

```php
**php bin/console generate:doctrine:crud**

```

这导致了一个交互式输出，如下所示：

![创建客户实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_08_03.jpg)

这导致了`src/Foggyline/CustomerBundle/Controller/CustomerController.php`目录的创建。它还在我们的`app/config/routing.yml`文件中添加了一个条目，如下所示：

```php
foggyline_customer_customer:
  resource: "@FoggylineCustomerBundle/Controller/CustomerController.php"
  type:     annotation
```

同样，视图文件是在`app/Resources/views/customer/`目录下创建的，这不是我们所期望的。我们希望它们在我们的模块`src/Foggyline/CustomerBundle/Resources/views/Default/customer/`目录下，所以我们需要将它们复制过去。此外，我们需要修改`CustomerController`中的所有`$this->render`调用，通过在每个模板路径后附加`FoggylineCustomerBundle:default: string`来实现。

## 修改安全配置

在我们继续进行模块内的实际更改之前，让我们想象一下我们的模块要求规定了某种安全配置以使其工作。这些要求规定我们需要对`app/config/security.yml`文件进行几处更改。我们首先编辑`providers`元素，添加以下条目：

```php
foggyline_customer:
  entity:
    class: FoggylineCustomerBundle:Customer
  property: username
```

这有效地将我们的`Customer`类定义为安全提供者，而`username`元素是存储用户身份的属性。

然后，在`encoders`元素下定义编码器类型，如下所示：

```php
Foggyline\CustomerBundle\Entity\Customer:
  algorithm: bcrypt
  cost: 12
```

这告诉 Symfony 在加密密码时使用`bcrypt`算法，算法成本为`12`。这样，我们的密码在保存到数据库中时就不会以明文形式出现。

然后，我们继续在`firewalls`元素下定义一个新的防火墙条目，如下所示：

```php
foggyline_customer:
  anonymous: ~
  provider: foggyline_customer
  form_login:
    login_path: foggyline_customer_login
    check_path: foggyline_customer_login
    default_target_path: customer_account
  logout:
    path:   /customer/logout
    target: /
```

这里发生了很多事情。我们的防火墙使用`anonymous: ~`定义来表示它实际上不需要用户登录即可查看某些页面。默认情况下，所有 Symfony 用户都被验证为匿名用户，如下图所示，在**Developer**工具栏上：

![修改安全配置](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_08_04.jpg)

`form_login`定义有三个属性。`login_path`和`check_path`指向我们的自定义路由`foggyline_customer_login`。当安全系统启动认证过程时，它将重定向用户到`foggyline_customer_login`路由，我们将很快实现所需的控制器逻辑和视图模板，以处理登录表单。一旦登录，`default_target_path`确定用户将被重定向到哪里。

最后，我们重用 Symfony 匿名用户功能，以排除某些页面被禁止。我们希望我们的非认证客户能够访问登录、注册和忘记密码页面。为了实现这一点，我们在`access_control`元素下添加以下条目：

```php
- { path: customer/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
- { path: customer/register, roles: IS_AUTHENTICATED_ANONYMOUSLY }
- { path: customer/forgotten_password, roles: IS_AUTHENTICATED_ANONYMOUSLY }
- { path: customer/account, roles: ROLE_USER }
- { path: customer/logout, roles: ROLE_USER }
- { path: customer/, roles: ROLE_ADMIN }
```

值得注意的是，这种处理模块和基本应用程序之间安全性的方法远非理想。这只是一个可能的例子，说明了我们如何实现这个模块所需的功能。

## 扩展客户实体

有了前面的`security.yml`添加，我们现在准备开始实际实现注册流程。首先，我们编辑`src/Foggyline/CustomerBundle/Entity/`目录中的`Customer`实体，使其实现`Symfony\Component\Security\Core\User\UserInterface`、`\Serializable`。这意味着需要实现以下方法：

```php
public function getSalt()
{
  return null;
}

public function getRoles()
{
  return array('ROLE_USER');
}

public function eraseCredentials()
{
}

public function serialize()
{
  return serialize(array(
    $this->id,
    $this->username,
    $this->password
  ));
}

public function unserialize($serialized)
{
  list (
    $this->id,
    $this->username,
    $this->password,
  ) = unserialize($serialized);
}
```

尽管所有密码都需要使用盐进行哈希处理，但在这种情况下`getSalt`函数是无关紧要的，因为`bcrypt`在内部已经处理了这个问题。`getRoles`函数是重要的部分。我们可以返回一个或多个个体客户将拥有的角色。为了简化，我们将为每个客户分配一个`ROLE_USER`角色。但是这可以很容易地更加健壮，以便将角色存储在数据库中。`eraseCredentials`函数只是一个清理方法，我们将其留空。

由于用户对象首先被反序列化、序列化并保存到每个请求的会话中，我们实现了`\Serializable`接口。序列化和反序列化的实际实现可以只包括一小部分客户属性，因为我们不需要将所有东西都存储在会话中。

在我们继续并开始实现注册、登录、忘记密码和其他部分之前，让我们先定义我们稍后要使用的所需服务。

## 创建订单服务

我们将创建一个`orders`服务，用于填充**我的账户**页面下可用的数据。稍后，其他模块可以覆盖此服务并注入真实的客户订单。要定义一个`orders`服务，我们通过在`src/Foggyline/CustomerBundle/Resources/config/services.xml`文件中在`services`元素下添加以下内容来进行编辑：

```php
<service id="foggyline_customer.customer_orders" class="Foggyline\CustomerBundle\Service\CustomerOrders">
</service>
```

然后，我们继续创建`src/Foggyline/CustomerBundle/Service/CustomerOrders.php`目录，内容如下：

```php
namespace Foggyline\CustomerBundle\Service;

class CustomerOrders
{
  public function getOrders()
  {
    return array(
      array(
        'id' => '0000000001',
        'date' => '23/06/2016 18:45',
        'ship_to' => 'John Doe',
        'order_total' => 49.99,
        'status' => 'Processing',
        'actions' => array(
          array(
            'label' => 'Cancel',
            'path' => '#'
          ),
          array(
            'label' => 'Print',
            'path' => '#'
          )
        )
      ),
    );
  }
}
```

`getOrders`方法在这里只是返回一些虚拟数据。我们可以很容易地使其返回一个空数组。理想情况下，我们希望它返回符合某些特定接口的某些类型元素的集合。

## 创建客户菜单服务

在上一个模块中，我们定义了一个填充客户菜单的`customer`服务，并填充了一些虚拟数据。现在我们将创建一个覆盖服务，根据客户登录状态填充菜单的实际客户数据。要定义一个`customer menu`服务，我们通过在`src/Foggyline/CustomerBundle/Resources/config/services.xml`文件中在`services`元素下添加以下内容来进行编辑：

```php
<service id="foggyline_customer.customer_menu" class="Foggyline\CustomerBundle\Service\Menu\CustomerMenu">
  <argument type="service" id="security.token_storage"/>
  <argument type="service" id="router"/>
</service>
```

在这里，我们将`token_storage`和`router`对象注入到我们的服务中，因为我们需要它们根据客户的登录状态构建菜单。

然后，我们继续创建`src/Foggyline/CustomerBundle/Service/Menu/CustomerMenu.php`目录，内容如下：

```php
namespace Foggyline\CustomerBundle\Service\Menu;

class CustomerMenu
{
  private $token;
  private $router;

  public function __construct(
    $tokenStorage,
    \Symfony\Bundle\FrameworkBundle\Routing\Router $router
  )
  {
    $this->token = $tokenStorage->getToken();
    $this->router = $router;
  }

  public function getItems()
  {
    $items = array();
    $user = $this->token->getUser();

    if ($user instanceof \Foggyline\CustomerBundle\Entity\Customer) {
      // customer authentication
      $items[] = array(
        'path' => $this->router->generate('customer_account'),
        'label' => $user->getFirstName() . ' ' . $user->getLastName(),
      );
      $items[] = array(
        'path' => $this->router->generate('customer_logout'),
        'label' => 'Logout',
      );
    } else {
      $items[] = array(
        'path' => $this->router->generate('foggyline_customer_login'),
        'label' => 'Login',
      );
      $items[] = array(
        'path' => $this->router->generate('foggyline_customer_register'),
        'label' => 'Register',
      );
    }

    return $items;
  }
}
```

在这里，我们看到一个基于用户登录状态构建菜单。这样，客户在登录时可以看到**注销**链接，未登录时可以看到**登录**链接。

然后，我们添加`src/Foggyline/CustomerBundle/DependencyInjection/Compiler/OverrideServiceCompilerPass.php`目录，内容如下：

```php
namespace Foggyline\CustomerBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class OverrideServiceCompilerPass implements CompilerPassInterface
{
  public function process(ContainerBuilder $container)
  {
    // Override the core module 'onsale' service
    $container->removeDefinition('customer_menu');
    $container->setDefinition('customer_menu', $container->getDefinition('foggyline_customer.customer_menu'));
  }
}
```

在这里，我们正在实际进行`customer_menu`服务覆盖。但是，这不会生效，直到我们通过添加以下内容来编辑`src/Foggyline/CustomerBundle/FoggylineCustomerBundle.php`目录的`build`方法：

```php
namespace Foggyline\CustomerBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Foggyline\CustomerBundle\DependencyInjection\Compiler\OverrideServiceCompilerPass;

class FoggylineCustomerBundle extends Bundle
{
  public function build(ContainerBuilder $container)
  {
    parent::build($container);;
    $container->addCompilerPass(new OverrideServiceCompilerPass());
  }
}
```

`addCompilerPass`方法调用接受我们的`OverrideServiceCompilerPass`实例，确保我们的服务覆盖将生效。

## 实现注册流程

要实现注册页面，我们首先修改`src/Foggyline/CustomerBundle/Controller/CustomerController.php`文件如下：

```php
/**
 * @Route("/register", name="foggyline_customer_register")
 */
public function registerAction(Request $request)
{
  // 1) build the form
  $user = new Customer();
  $form = $this->createForm(CustomerType::class, $user);

  // 2) handle the submit (will only happen on POST)
  $form->handleRequest($request);
  if ($form->isSubmitted() && $form->isValid()) {

    // 3) Encode the password (you could also do this via Doctrine listener)
    $password = $this->get('security.password_encoder')
    ->encodePassword($user, $user->getPlainPassword());
    $user->setPassword($password);

    // 4) save the User!
    $em = $this->getDoctrine()->getManager();
    $em->persist($user);
    $em->flush();

    // ... do any other work - like sending them an email, etc
    // maybe set a "flash" success message for the user

    return $this->redirectToRoute('customer_account');
  }

  return $this->render(
    'FoggylineCustomerBundle:default:customer/register.html.twig',
    array('form' => $form->createView())
  );
}
```

注册页面使用标准的自动生成的客户 CRUD 表单，只需将其指向`src/Foggyline/CustomerBundle/Resources/views/Default/customer/register.html.twig`模板文件，内容如下：

```php
{% extends 'base.html.twig' %}
{% block body %}
  {{ form_start(form) }}
  {{ form_widget(form) }}
  <button type="submit">Register!</button>
  {{ form_end(form) }}
{% endblock %}
```

一旦这两个文件就位，我们的注册功能应该就能正常工作了。

## 实现登录流程

我们将在独立的`/customer/login` URL 上实现登录页面，因此我们通过添加以下`loginAction`函数来编辑`CustomerController.php`文件：

```php
/**
 * Creates a new Customer entity.
 *
 * @Route("/login", name="foggyline_customer_login")
 */
public function loginAction(Request $request)
{
  $authenticationUtils = $this->get('security.authentication_utils');

  // get the login error if there is one
  $error = $authenticationUtils->getLastAuthenticationError();

  // last username entered by the user
  $lastUsername = $authenticationUtils->getLastUsername();

  return $this->render(
    'FoggylineCustomerBundle:default:customer/login.html.twig',
    array(
      // last username entered by the user
      'last_username' => $lastUsername,
      'error'         => $error,
    )
  );
}
```

在这里，我们只是检查用户是否已经尝试登录，如果是，我们将将该信息传递给模板，以及潜在的错误。然后我们编辑`src/Foggyline/CustomerBundle/Resources/views/Default/customer/login.html.twig`文件，内容如下：

```php
{% extends 'base.html.twig' %}
{% block body %}
{% if error %}
<div>{{ error.messageKey|trans(error.messageData, 'security') }}</div>
{% endif %}

<form action="{{ path('foggyline_customer_login') }}" method="post">
  <label for="username">Username:</label>
  <input type="text" id="username" name="_username" value="{{ last_username }}"/>
  <label for="password">Password:</label>
  <input type="password" id="password" name="_password"/>
  <button type="submit">login</button>
</form>

<div class="row">
  <a href="{{ path('customer_forgotten_password') }}">Forgot your password?</a>
</div>
{% endblock %}
```

一旦登录，用户将被重定向到`/customer/account`页面。我们通过在`CustomerController.php`文件中添加`accountAction`方法来创建此页面，如下所示：

```php
/**
 * Finds and displays a Customer entity.
 *
 * @Route("/account", name="customer_account")
 * @Method({"GET", "POST"})
 */
public function accountAction(Request $request)
{
  if (!$this->get('security.authorization_checker')->isGranted('ROLE_USER')) {
    throw $this->createAccessDeniedException();
  }

  if ($customer = $this->getUser()) {

    $editForm = $this->createForm('Foggyline\CustomerBundle\Form\CustomerType', $customer, array( 'action' => $this->generateUrl('customer_account')));
    $editForm->handleRequest($request);

    if ($editForm->isSubmitted() && $editForm->isValid()) {
      $em = $this->getDoctrine()->getManager();
      $em->persist($customer);
      $em->flush();

      $this->addFlash('success', 'Account updated.');
      return $this->redirectToRoute('customer_account');
    }

    return $this->render('FoggylineCustomerBundle:default:customer/account.html.twig', array(
    'customer' => $customer,
    'form' => $editForm->createView(),
    'customer_orders' => $this->get('foggyline_customer.customer_orders')->getOrders()
    ));
  } else {
    $this->addFlash('notice', 'Only logged in customers can access account page.');
    return $this->redirectToRoute('foggyline_customer_login');
  }
}
```

使用`$this->getUser()`我们正在检查已登录用户是否已设置，如果是，则将其信息传递给模板。然后我们编辑`src/Foggyline/CustomerBundle/Resources/views/Default/customer/account.html.twig`文件，内容如下：

```php
{% extends 'base.html.twig' %}
{% block body %}
<h1>My Account</h1>
{{ form_start(form) }}
<div class="row">
  <div class="medium-6 columns">
    {{ form_row(form.email) }}
    {{ form_row(form.username) }}
    {{ form_row(form.plainPassword.first) }}
    {{ form_row(form.plainPassword.second) }}
    {{ form_row(form.firstName) }}
    {{ form_row(form.lastName) }}
    {{ form_row(form.company) }}
    {{ form_row(form.phoneNumber) }}
  </div>
  <div class="medium-6 columns">
    {{ form_row(form.country) }}
    {{ form_row(form.state) }}
    {{ form_row(form.city) }}
    {{ form_row(form.postcode) }}
    {{ form_row(form.street) }}
    <button type="submit">Save</button>
  </div>
</div>
{{ form_end(form) }}
<!-- customer_orders -->
{% endblock %}
```

通过这样做，我们解决了**我的账户**页面的实际客户信息部分。在当前状态下，该页面应该呈现一个编辑表单，如下截图所示，使我们能够编辑所有客户信息：

![实现登录过程](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_08_05.jpg)

然后，我们通过以下方式替换`<!-- customer_orders -->`：

```php
{% block customer_orders %}
<h2>My Orders</h2>
<div class="row">
  <table>
    <thead>
      <tr>
        <th width="200">Order Id</th>
        <th>Date</th>
        <th width="150">Ship To</th>
        <th width="150">Order Total</th>
        <th width="150">Status</th>
        <th width="150">Actions</th>
      </tr>
    </thead>
    <tbody>
      {% for order in customer_orders %}
      <tr>
        <td>{{ order.id }}</td>
        <td>{{ order.date }}</td>
        <td>{{ order.ship_to }}</td>
        <td>{{ order.order_total }}</td>
        <td>{{ order.status }}</td>
        <td>
          <div class="small button-group">
            {% for action in order.actions %}
            <a class="button" href="{{ action.path }}">{{ action.label }}</a>
            {% endfor %}
          </div>
        </td>
      </tr>
      {% endfor %}
    /tbody>
  </table>
</div>
{% endblock %}
```

现在应该呈现**My Account**页面的**My Orders**部分，如下所示：

实现登录流程

这只是来自`src/Foggyline/CustomerBundle/Resources/config/services.xml`中定义的服务的虚拟数据。在后面的章节中，当我们到达销售模块时，我们将确保它覆盖`foggyline_customer.customer_orders`服务，以便在这里插入真实的客户数据。

## 实现注销流程

在定义防火墙时，我们对`security.yml`所做的更改之一是配置注销路径，我们将其指向`/customer/logout`。该路径的实现在`CustomerController.php`文件中如下：

```php
/**
 * @Route("/logout", name="customer_logout")
 */
public function logoutAction()
{

}
```

注意，`logoutAction`方法实际上是空的。没有实际的实现。不需要实现，因为 Symfony 拦截请求并为我们处理注销。但是，我们需要定义这个路由，因为我们在`system.xml`文件中引用了它。

## 管理忘记密码

忘记密码功能将作为一个单独的页面实现。我们通过向`CustomerController.php`文件添加`forgottenPasswordAction`函数来编辑它，如下所示：

```php
/**
 * @Route("/forgotten_password", name="customer_forgotten_password")
 * @Method({"GET", "POST"})
 */
public function forgottenPasswordAction(Request $request)
{

  // Build a form, with validation rules in place
  $form = $this->createFormBuilder()
  ->add('email', EmailType::class, array(
    'constraints' => new Email()
  ))
  ->add('save', SubmitType::class, array(
    'label' => 'Reset!',
    'attr' => array('class' => 'button'),
  ))
  ->getForm();

  // Check if this is a POST type request and if so, handle form
  if ($request->isMethod('POST')) {
    $form->handleRequest($request);

    if ($form->isSubmitted() && $form->isValid()) {
      $this->addFlash('success', 'Please check your email for reset password.');

      // todo: Send an email out to website admin or something...

      return $this->redirect($this->generateUrl('foggyline_customer_login'));
    }
  }

  // Render "contact us" page
  return $this->render('FoggylineCustomerBundle:default:customer/forgotten_password.html.twig', array(
      'form' => $form->createView()
    ));
}
```

在这里，我们仅检查 HTTP 请求是 GET 还是 POST，然后发送电子邮件或加载模板。为了简单起见，我们实际上没有实现实际的电子邮件发送。这是需要在本书之外解决的问题。渲染的模板指向`src/Foggyline/CustomerBundle/Resources/views/Default/customer/forgotten_password.html.twig`文件，内容如下：

```php
{% extends 'base.html.twig' %}
{% block body %}
<div class="row">
  <h1>Forgotten Password</h1>
</div>

<div class="row">
  {{ form_start(form) }}
  {{ form_widget(form) }}
  {{ form_end(form) }}
</div>
{% endblock %}
```

# 单元测试

除了自动生成的`Customer`实体及其 CRUD 控制器之外，我们创建了两个自定义服务类作为这个模块的一部分。由于我们不追求完整的代码覆盖率，我们将仅在单元测试中涵盖`CustomerOrders`和`CustomerMenu`服务类。

我们首先在`phpunit.xml.dist`文件的`testsuites`元素下添加以下行：

```php
<directory>src/Foggyline/CustomerBundle/Tests</directory>
```

有了这个，从我们商店的根目录运行`phpunit`命令应该能够捕捉到我们在`src/Foggyline/CustomerBundle/Tests/`目录下定义的任何测试。

现在让我们继续为我们的`CustomerOrders`服务创建一个测试。我们通过创建一个`src/Foggyline/CustomerBundle/Tests/Service/CustomerOrders.php`文件来实现：

```php
namespace Foggyline\CustomerBundle\Tests\Service;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class CustomerOrders extends KernelTestCase
{
  private $container;

  public function setUp()
  {
    static::bootKernel();
    $this->container = static::$kernel->getContainer();
  }

  public function testGetItemsViaService()
  {
    $orders = $this->container->get('foggyline_customer.customer_orders');
    $this->assertNotEmpty($orders->getOrders());
  }

  public function testGetItemsViaClass()
  {
    $orders = new \Foggyline\CustomerBundle\Service\CustomerOrders();
    $this->assertNotEmpty($orders->getOrders());
  }
}
```

这里我们总共有两个测试，一个是通过服务实例化类，另一个是直接实例化。我们仅使用`setUp`方法来设置`container`属性，然后在`testGetItemsViaService`方法中重用它。

接下来，我们在目录中创建`CustomerMenu`测试如下：

```php
namespace Foggyline\CustomerBundle\Tests\Service\Menu;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class CustomerMenu extends KernelTestCase
{
  private $container;
  private $tokenStorage;
  private $router;

  public function setUp()
  {
    static::bootKernel();
    $this->container = static::$kernel->getContainer();
    $this->tokenStorage = $this->container->get('security.token_storage');
    $this->router = $this->container->get('router');
  }

  public function testGetItemsViaService()
  {
    $menu = $this->container->get('foggyline_customer.customer_menu');
    $this->assertNotEmpty($menu->getItems());
  }

  public function testGetItemsViaClass()
  {
    $menu = new \Foggyline\CustomerBundle\Service\Menu\CustomerMenu(
      $this->tokenStorage,
      $this->router
    );

    $this->assertNotEmpty($menu->getItems());
  }
}
```

现在，如果我们运行`phpunit`命令，我们应该能够看到我们的测试被捕捉并与其他测试一起执行。我们甚至可以通过执行带有完整类路径的`phpunit`命令来专门针对这两个测试，如下所示：

```php
**phpunit src/Foggyline/CustomerBundle/Tests/Service/CustomerOrders.php**
**phpunit src/Foggyline/CustomerBundle/Tests/Service/Menu/CustomerMenu.php**

```

# 功能测试

自动生成的 CRUD 工具在`src/Foggyline/CustomerBundle/Tests/Controller/`目录中为我们生成了`CustomerControllerTest.php`文件。在上一章中，我们展示了如何向`static::createClient`传递身份验证参数，以便模拟用户登录。然而，这不同于我们的客户将使用的登录。我们不再使用基本的 HTTP 身份验证，而是一个完整的登录表单。

为了解决登录表单测试问题，让我们继续编辑`src/Foggyline/CustomerBundle/Tests/Controller/CustomerControllerTest.php`文件如下：

```php
namespace Foggyline\CustomerBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class CustomerControllerTest extends WebTestCase
{
  private $client = null;

  public function setUp()
  {
    $this->client = static::createClient();
  }

  public function testMyAccountAccess()
  {
    $this->logIn();
    $crawler = $this->client->request('GET', '/customer/account');

    $this->assertTrue($this->client->getResponse()->
      isSuccessful());
    $this->assertGreaterThan(0, $crawler->filter('html:contains("My Account")')->count());
  }

  private function logIn()
  {
    $session = $this->client->getContainer()->get('session');
    $firewall = 'foggyline_customer'; // firewall name
    $em = $this->client->getContainer()->get('doctrine')->getManager();
    $user = $em->getRepository('FoggylineCustomerBundle:Customer')->findOneByUsername('john@test.loc');
    $token = new UsernamePasswordToken($user, null, $firewall, array('ROLE_USER'));
    $session->set('_security_' . $firewall, serialize($token));
    $session->save();
    $cookie = new Cookie($session->getName(), $session->getId());
    $this->client->getCookieJar()->set($cookie);
  }
}
```

在这里，我们首先创建了`logIn`方法，其目的是通过将正确的令牌值设置到会话中，并通过 cookie 将该会话 ID 传递给客户端来模拟登录。然后我们创建了`testMyAccountAccess`方法，该方法首先调用`logIn`方法，然后检查爬虫是否能够访问“我的账户”页面。这种方法的好处在于，我们不必编写用户密码，只需编写用户名。

现在，让我们继续处理客户注册表单，通过向`CustomerControllerTest`添加以下内容：

```php
public function testRegisterForm()
{
  $crawler = $this->client->request('GET', '/customer/register');
  $uniqid = uniqid();
  $form = $crawler->selectButton('Register!')->form(array(
    'customer[email]' => 'john_' . $uniqid . '@test.loc',
    'customer[username]' => 'john_' . $uniqid,
    'customer[plainPassword][first]' => 'pass123',
    'customer[plainPassword][second]' => 'pass123',
    'customer[firstName]' => 'John',
    'customer[lastName]' => 'Doe',
    'customer[company]' => 'Foggyline',
    'customer[phoneNumber]' => '00 385 111 222 333',
    'customer[country]' => 'HR',
    'customer[state]' => 'Osijek',
    'customer[city]' => 'Osijek',
    'customer[postcode]' => '31000',
    'customer[street]' => 'The Yellow Street',
  ));

  $this->client->submit($form);
  $crawler = $this->client->followRedirect();
  //var_dump($this->client->getResponse()->getContent());
  $this->assertGreaterThan(0, $crawler->filter('html:contains("customer/login")')->count());
}
```

在上一章中，我们已经看到了类似于这个的测试。在这里，我们只是打开了一个客户/注册页面，然后找到一个带有“注册！”标签的按钮，以便我们可以通过它获取整个表单。然后我们设置所有必需的表单数据，并模拟表单提交。如果成功，我们观察重定向主体，并断言其中的预期值。

现在运行`phpunit`命令应该成功执行我们的测试。

# 总结

在本章中，我们构建了一个微型但功能齐全的客户模块。该模块假定我们在`security.yml`文件上进行了一定程度的设置，如果我们要重新分发它，可以将其作为模块文档的一部分进行覆盖。这些更改包括定义我们自己的自定义防火墙和自定义安全提供程序。安全提供程序指向我们的`customer`类，而该类又是按照 Symfony`UserInterface`构建的。然后我们构建了注册、登录和忘记密码表单。尽管每个表单都带有一组最小的功能，但我们看到构建完全自定义的注册和登录系统是多么简单。

此外，我们通过使用专门定义的服务在“我的账户”页面下设置“我的订单”部分，采取了一些前瞻性的做法。这绝对是理想的做法，它有其作用，因为我们稍后将从“销售”模块中清晰地覆盖此服务。

在接下来的章节中，我们将构建一个“支付”模块。


# 第九章：构建支付模块

支付模块为我们的网店提供了进一步销售功能的基础。当我们到达即将推出的销售模块的结账流程时，它将使我们能够实际选择支付方式。支付方式通常可以是各种类型。有些可以是静态的，如支票和货到付款，而其他一些可以是常规信用卡，如 Visa、MasterCard、American Express、Discover 和 Switch/Solo。在本章中，我们将讨论这两种类型。

在本章中，我们将研究以下主题：

+   要求

+   依赖

+   实施

+   单元测试

+   功能测试

# 要求

我们的应用要求在第四章下定义，*模块化网店应用的需求规范*，实际上并没有说明我们需要实现的支付方式类型。因此，在本章中，我们将开发两种支付方式：卡支付和支票支付。关于信用卡支付，我们不会连接到真实的支付处理器，但其他所有操作都将按照与信用卡一起工作的方式进行。

理想情况下，我们希望通过接口完成以下操作：

```php
namespace Foggyline\SalesBundle\Interface;

interface Payment
{
  function authorize();
  function capture();
  function cancel();
}
```

这将需要`SalesBundle`模块，但我们还没有开发。因此，我们将使用一个简单的 Symfony`controller`类来进行支付方法，该类提供了自己的方式来处理以下功能：

+   函数`authorize();`

+   函数`capture();`

+   函数`cancel();`

`authorize`方法用于仅授权交易而不实际执行交易的情况。结果是一个交易 ID，我们未来的`SalesBundle`模块可以存储并重复使用以进行进一步的`capture`和`cancel`操作。`capture`方法首先执行授权操作，然后捕获资金。`cancel`方法基于先前存储的授权令牌执行取消操作。

我们将通过标记的 Symfony 服务公开我们的支付方式。服务的标记是一个很好的功能，它使我们能够查看容器和所有标记为相同标记的服务，这是我们可以用来获取所有`paymentmethod`服务的东西。标记命名必须遵循一定的模式，这是我们作为应用程序创建者所强加给自己的。考虑到这一点，我们将使用`name`,`payment_method`标记每个支付服务。

稍后，`SalesBundle`模块将获取并使用所有标记为`payment_method`的服务，然后在内部使用它们生成可用支付方式的列表。

# 依赖

该模块不依赖于任何其他模块。但是，首先构建`SalesBundle`模块，然后公开一些`payment`模块可能使用的接口可能更方便。

# 实施

我们首先创建一个名为`Foggyline\PaymentBundle`的新模块。我们通过运行以下命令来完成这个操作：

```php
**php bin/console generate:bundle --namespace=Foggyline/PaymentBundle**

```

该命令触发一个交互式过程，沿途询问我们几个问题，如下所示：

![实施](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_09_01.jpg)

完成后，文件`app/AppKernel.php`和`app/config/routing.yml`将自动修改。`AppKernel`类的`registerBundles`方法已添加到`$bundles`数组下的以下行：

```php
new Foggyline\PaymentBundle\FoggylinePaymentBundle(),
```

`routing.yml`已更新为以下条目：

```php
foggyline_payment:
  resource: "@FoggylinePaymentBundle/Resources/config/routing.xml"
  prefix:   /
```

为了避免与核心应用程序代码冲突，我们需要将`prefix: /`更改为`prefix: /payment/`。

## 创建卡实体

尽管在本章中我们不会在数据库中存储任何信用卡，但我们希望重用 Symfony 自动生成的 CRUD 功能，以便为我们提供信用卡模型和表单。让我们继续创建一个`Card`实体。我们将使用控制台来实现，如下所示：

```php
php bin/console generate:doctrine:entity
```

该命令触发交互式生成器，为实体快捷方式提供`FoggylinePaymentBundle:Card`，我们还需要提供实体属性。我们想要用以下字段对`Card`实体建模：

+   `card_type`: string

+   `card_number`: string

+   `expiry_date`: date

+   `security_code`: string

完成后，生成器将在`src/Foggyline/PaymentBundle/`目录中创建`Entity/Card.php`和`Repository/CardRepository.php`。我们现在可以更新数据库，以便引入`Card`实体，如下所示：

```php
php bin/console doctrine:schema:update --force
```

有了实体，我们准备生成其 CRUD。我们将使用以下命令来实现：

```php
php bin/console generate:doctrine:crud
```

这将导致创建`src/Foggyline/PaymentBundle/Controller/CardController.php`文件。它还会向我们的`app/config/routing.yml`文件添加一个条目，如下所示：

```php
foggyline_payment_card:
  resource: "@FoggylinePaymentBundle/Controller/CardController.php"
  type:    annotation
```

同样，视图文件是在`app/Resources/views/card/`目录下创建的。由于我们实际上不会围绕卡片执行任何与 CRUD 相关的操作，因此我们可以继续删除所有生成的视图文件，以及`CardController`类的整个主体。此时，我们应该有`Card`实体，`CardType`表单和空的`CardController`类。

### 创建卡支付服务

卡支付服务将为我们未来的销售模块提供其结账流程所需的相关信息。它的作用是提供订单的支付方法标签、代码和处理 URL，如`authorize`、`capture`和`cancel`。

我们将首先在`src/Foggyline/PaymentBundle/Resources/config/services.xml`文件的 services 元素下定义以下服务：

```php
<service id="foggyline_payment.card_payment"class="Foggyline\PaymentBundle\Service\CardPayment">
  <argument type="service" id="form.factory"/>
  <argument type="service" id="router"/>
  <tag name="payment_method"/>
</service>
```

该服务接受两个参数：一个是`form.factory`，另一个是`router`。`form.factory`将在服务内部用于为`CardType`表单创建表单视图。标签在这里是一个关键元素，因为我们的`SalesBundle`模块将根据分配给服务的`payment_method`标签来寻找支付方法。

现在我们需要在`src/Foggyline/PaymentBundle/Service/CardPayment.php`文件中创建实际的服务类，如下所示：

```php
namespace Foggyline\PaymentBundle\Service;

use Foggyline\PaymentBundle\Entity\Card;

class CardPayment
{
  private $formFactory;
  private $router;

  public function __construct(
    $formFactory,
    \Symfony\Bundle\FrameworkBundle\Routing\Router $router
  )
  {
    $this->formFactory = $formFactory;
    $this->router = $router;
  }

  public function getInfo()
  {
    $card = new Card();
    $form = $this->formFactory->create('Foggyline\PaymentBundle\Form\CardType', $card);

    return array(
      'payment' => array(
      'title' =>'Foggyline Card Payment',
      'code' =>'card_payment',
      'url_authorize' => $this->router->generate('foggyline_payment_card_authorize'),
      'url_capture' => $this->router->generate('foggyline_payment_card_capture'),
      'url_cancel' => $this->router->generate('foggyline_payment_card_cancel'),
      'form' => $form->createView()
      )
    );
  }
}
```

`getInfo`方法将为我们未来的`SalesBundle`模块提供必要的信息，以便它构建结账流程的支付步骤。我们在这里传递了三种不同类型的 URL：`authorize`，`capture`和`cancel`。这些路由目前还不存在，我们将很快创建它们。我们的想法是将支付操作和流程转移到实际的`payment`方法。我们未来的`SalesBundle`模块只会对这些支付 URL 进行**AJAX POST**，并期望获得成功或错误的 JSON 响应。成功的响应应该产生某种交易 ID，错误的响应应该产生一个标签消息显示给用户。

## 创建卡支付控制器和路由

我们将通过向`src/Foggyline/PaymentBundle/Resources/config/routing.xml`文件添加以下路由定义来编辑它：

```php
<route id="foggyline_payment_card_authorize" path="/card/authorize">
  <default key="_controller">FoggylinePaymentBundle:Card:authorize</default>
</route>

<route id="foggyline_payment_card_capture" path="/card/capture">
  <default key="_controller">FoggylinePaymentBundle:Card:capture</default>
</route>

<route id="foggyline_payment_card_cancel" path="/card/cancel">
  <default key="_controller">FoggylinePaymentBundle:Card:cancel</default>
</route>
```

然后，我们将通过添加以下内容来编辑`CardController`类的主体：

```php
public function authorizeAction(Request $request)
{
  $transaction = md5(time() . uniqid()); // Just a dummy string, simulating some transaction id, if any

  if ($transaction) {
    return new JsonResponse(array(
      'success' => $transaction
    ));
  }

  return new JsonResponse(array(
    'error' =>'Error occurred while processing Card payment.'
  ));
}

public function captureAction(Request $request)
{
  $transaction = md5(time() . uniqid()); // Just a dummy string, simulating some transaction id, if any

  if ($transaction) {
    return new JsonResponse(array(
      'success' => $transaction
    ));
  }

  return new JsonResponse(array(
    'error' =>'Error occurred while processing Card payment.'
  ));
}

public function cancelAction(Request $request)
{
  $transaction = md5(time() . uniqid()); // Just a dummy string, simulating some transaction id, if any

  if ($transaction) {
    return new JsonResponse(array(
      'success' => $transaction
    ));
  }

  return new JsonResponse(array(
    'error' =>'Error occurred while processing Card payment.'
  ));
}
```

现在，我们应该能够访问像`/app_dev.php/payment/card/authorize`这样的 URL，并看到`authorizeAction`的输出。这里给出的实现是虚拟的。在本章中，我们不打算连接到真实的支付处理 API。对我们来说重要的是，`sales`模块在结账过程中，会通过`payment_method`标记的服务的`getInfo`方法中的`['payment']['form']`键来渲染任何可能的表单视图。这意味着结账过程应该在信用卡付款下显示一个信用卡表单。结账的行为将被编码，以便如果选择了带有表单的付款，并且点击了**下订单**按钮，那么付款表单将阻止结账过程继续进行，直到付款表单被提交到支付本身定义的授权或捕获 URL。当我们到达`SalesBundle`模块时，我们将更详细地讨论这一点。

## 创建支票付款服务

除了信用卡付款方式，让我们继续定义另一种静态付款，称为**支票**。

我们将从`src/Foggyline/PaymentBundle/Resources/config/services.xml`文件的 services 元素下定义以下服务开始：

```php
<service id="foggyline_payment.check_money"class="Foggyline\PaymentBundle\Service\CheckMoneyPayment">
  <argument type="service" id="router"/>
  <tag name="payment_method"/>
</service>
```

这里定义的`service`只接受一个`router`参数。标签名称与信用卡付款服务相同。

然后，我们将创建`src/Foggyline/PaymentBundle/Service/CheckMoneyPayment.php`文件，内容如下：

```php
namespace Foggyline\PaymentBundle\Service;

class CheckMoneyPayment
{
  private $router;

  public function __construct(
    \Symfony\Bundle\FrameworkBundle\Routing\Router $router
  )
  {
    $this->router = $router;
  }

  public function getInfo()
  {
    return array(
      'payment' => array(
        'title' =>'Foggyline Check Money Payment',
        'code' =>'check_money',
        'url_authorize' => $this->router->generate('foggyline_payment_check_money_authorize'),
        'url_capture' => $this->router->generate('foggyline_payment_check_money_capture'),
        'url_cancel' => $this->router->generate('foggyline_payment_check_money_cancel'),
        //'form' =>''
      )
    );
  }
}
```

与信用卡付款不同，支票付款在`getInfo`方法下没有定义表单键。这是因为没有信用卡条目需要定义。它只是一个静态付款方式。但是，我们仍然需要定义`authorize`、`capture`和`cancel`的 URL，即使它们的实现可能只是一个简单的 JSON 响应，带有成功或错误键。

## 创建支票付款控制器和路由

一旦支票付款服务就位，我们就可以继续为其创建必要的路由。我们将首先在`src/Foggyline/PaymentBundle/Resources/config/routing.xml`文件中添加以下路由定义：

```php
<route id="foggyline_payment_check_money_authorize"path="/check_money/authorize">
  <default key="_controller">FoggylinePaymentBundle:CheckMoney:authorize</default>
</route>

<route id="foggyline_payment_check_money_capture"path="/check_money/capture">
  <default key="_controller">FoggylinePaymentBundle:CheckMoney:capture</default>
</route>

<route id="foggyline_payment_check_money_cancel"path="/check_money/cancel">
  <default key="_controller">FoggylinePaymentBundle:CheckMoney:cancel</default>
</route>
```

然后，我们将创建`src/Foggyline/PaymentBundle/Controller/CheckMoneyController.php`文件，内容如下：

```php
namespace Foggyline\PaymentBundle\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class CheckMoneyController extends Controller
{
  public function authorizeAction(Request $request)
  {
    $transaction = md5(time() . uniqid());
    return new JsonResponse(array(
      'success' => $transaction
    ));
  }

  public function captureAction(Request $request)
  {
    $transaction = md5(time() . uniqid());
    return new JsonResponse(array(
      'success' => $transaction
    ));
  }

  public function cancelAction(Request $request)
  {
    $transaction = md5(time() . uniqid());
    return new JsonResponse(array(
      'success' => $transaction
    ));
  }
}
```

与信用卡付款类似，这里我们添加了`authorize`、`capture`和`cancel`方法的简单虚拟实现。这些方法的响应将在后面的`SalesBundle`模块中使用。我们可以很容易地从这些方法中实现更健壮的功能，但这超出了本章的范围。

# 单元测试

我们的`FoggylinePaymentBundle`模块非常简单。它只提供两种付款方式：信用卡和支票。它通过两个简单的`service`类来实现。由于我们不追求完整的代码覆盖率测试，我们将只在单元测试中覆盖`CardPayment`和`CheckMoneyPayment`服务类。

我们将首先在`phpunit.xml.dist`文件的`testsuites`元素下添加以下行：

```php
<directory>src/Foggyline/PaymentBundle/Tests</directory>
```

有了这个设置，从商店的根目录运行`phpunit`命令应该会捕捉到我们在`src/Foggyline/PaymentBundle/Tests/`目录下定义的任何测试。

现在，让我们继续为我们的`CardPayment`服务创建一个测试。我们将创建一个`src/Foggyline/PaymentBundle/Tests/Service/CardPaymentTest.php`文件，内容如下：

```php
namespace Foggyline\PaymentBundle\Tests\Service;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class CardPaymentTest extends KernelTestCase
{
  private $container;
  private $formFactory;
  private $router;

  public function setUp()
  {
    static::bootKernel();
    $this->container = static::$kernel->getContainer();
    $this->formFactory = $this->container->get('form.factory');
    $this->router = $this->container->get('router');
  }

  public function testGetInfoViaService()
  {
    $payment = $this->container->get('foggyline_payment.card_payment');
    $info = $payment->getInfo();
    $this->assertNotEmpty($info);
    $this->assertNotEmpty($info['payment']['form']);
  }

  public function testGetInfoViaClass()
  {
    $payment = new \Foggyline\PaymentBundle\Service\CardPayment(
       $this->formFactory,
       $this->router
    );

    $info = $payment->getInfo();
    $this->assertNotEmpty($info);
    $this->assertNotEmpty($info['payment']['form']);
  }
}
```

在这里，我们运行了两个简单的测试，以查看我们是否可以通过容器或直接实例化一个服务，并简单地调用它的`getInfo`方法。预期该方法将返回一个包含`['payment']['form']`键的响应。

现在，让我们继续为我们的`CheckMoneyPayment`服务创建一个测试。我们将创建一个`src/Foggyline/PaymentBundle/Tests/Service/CheckMoneyPaymentTest.php`文件，内容如下：

```php
namespace Foggyline\PaymentBundle\Tests\Service;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class CheckMoneyPaymentTest extends KernelTestCase
{
  private $container;
  private $router;

  public function setUp()
  {
    static::bootKernel();
    $this->container = static::$kernel->getContainer();
    $this->router = $this->container->get('router');
  }

  public function testGetInfoViaService()
  {
    $payment = $this->container->get('foggyline_payment.check_money');
    $info = $payment->getInfo();
    $this->assertNotEmpty($info);
  }

  public function testGetInfoViaClass()
  {
    $payment = new \Foggyline\PaymentBundle\Service\CheckMoneyPayment(
        $this->router
      );

    $info = $payment->getInfo();
    $this->assertNotEmpty($info);
  }
}
```

同样，在这里我们也有两个简单的测试：一个通过容器获取`payment`方法，另一个直接通过一个类获取。不同之处在于我们没有检查`getInfo`方法响应中是否存在表单键。

# 功能测试

我们的模块有两个控制器类，我们希望测试它们的响应。我们要确保`CardController`和`CheckMoneyController`类的`authorize`、`capture`和`cancel`方法是有效的。

我们首先创建了一个`src/Foggyline/PaymentBundle/Tests/Controller/CardControllerTest.php`文件，内容如下：

```php
namespace Foggyline\PaymentBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class CardControllerTest extends WebTestCase
{
  private $client;
  private $router;

  public function setUp()
  {
    $this->client = static::createClient();
    $this->router = $this->client->getContainer()->get('router');
  }

  public function testAuthorizeAction()
  {
    $this->client->request('GET', $this->router->generate('foggyline_payment_card_authorize'));
    $this->assertTests();
  }

  public function testCaptureAction()
  {
    $this->client->request('GET', $this->router->generate('foggyline_payment_card_capture'));
    $this->assertTests();
  }

  public function testCancelAction()
  {
    $this->client->request('GET', $this->router->generate('foggyline_payment_card_cancel'));
    $this->assertTests();
  }

  private function assertTests()
  {
    $this->assertSame(200, $this->client->getResponse()->getStatusCode());
    $this->assertSame('application/json', $this->client->getResponse()->headers->get('Content-Type'));
    $this->assertContains('success', $this->client->getResponse()->getContent());
    $this->assertNotEmpty($this->client->getResponse()->getContent());
  }
}
```

然后我们创建了`src/Foggyline/PaymentBundle/Tests/Controller/CheckMoneyControllerTest.php`，内容如下：

```php
namespace Foggyline\PaymentBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class CheckMoneyControllerTest extends WebTestCase
{
  private $client;
  private $router;

  public function setUp()
  {
    $this->client = static::createClient();
    $this->router = $this->client->getContainer()->get('router');
  }

  public function testAuthorizeAction()
  {
    $this->client->request('GET', $this->router->generate('foggyline_payment_check_money_authorize'));
    $this->assertTests();
  }

  public function testCaptureAction()
  {
    $this->client->request('GET', $this->router->generate('foggyline_payment_check_money_capture'));
    $this->assertTests();
  }

  public function testCancelAction()
  {
    $this->client->request('GET', $this->router->generate('foggyline_payment_check_money_cancel'));
    $this->assertTests();
  }

  private function assertTests()
  {
    $this->assertSame(200, $this->client->getResponse()->getStatusCode());
    $this->assertSame('application/json', $this->client->getResponse()->headers->get('Content-Type'));
    $this->assertContains('success', $this->client->getResponse()->getContent());
    $this->assertNotEmpty($this->client->getResponse()->getContent());
  }
}
```

这两个测试几乎是相同的。它们包含了对`authorize`、`capture`和`cancel`方法的测试。由于我们的方法是使用固定的成功 JSON 响应实现的，所以这里没有什么意外。然而，我们可以通过将我们的付款方法扩展为更强大的东西来轻松地进行调试。

# 总结

在本章中，我们构建了一个具有两种付款方法的付款模块。信用卡付款方法是为了模拟涉及信用卡的付款。因此，它包括一个表单作为其`getInfo`方法的一部分。另一方面，支票付款是模拟一个静态的付款方法 - 不包括任何形式的信用卡。这两种方法都是作为虚拟方法实现的，这意味着它们实际上并没有与任何外部付款处理器进行通信。

我们的想法是创建一个最小的结构，展示如何开发一个简单的付款模块以进行进一步的定制。我们通过将每种付款方法公开为一个标记服务来实现这一点。使用`payment_method`标记是一种共识，因为我们是构建完整应用程序的人，所以我们可以选择如何在`sales`模块中实现这一点。通过为每种付款方法使用相同的标记名称，我们有效地为未来的`sales`模块创建了条件，以便选择所有的付款方法并在其结账流程下呈现它们。

在接下来的章节中，我们将构建一个**shipment**模块。
