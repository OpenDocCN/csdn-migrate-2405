# PHP YII Web 应用开发（二）

> 原文：[`zh.annas-archive.org/md5/6008a5c78f9d1deb914065f1c36d5b5a`](https://zh.annas-archive.org/md5/6008a5c78f9d1deb914065f1c36d5b5a)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：用户管理和身份验证

我们在很短的时间内取得了很大的进展。我们已经奠定了 TrackStar 应用程序的基本基础。现在我们可以管理项目和项目内的问题，这是该应用程序的主要目的。当然，还有很多工作要做。

回到第三章 *TrackStar 应用程序*，当我们介绍这个应用程序时，我们将其描述为一个基于用户的应用程序，它提供了创建用户帐户并在用户经过身份验证和授权后授予对应用程序功能的能力。为了使这个应用程序对不止一个人有用，我们需要添加在项目内管理用户的能力。这将是接下来两章的重点。

# 功能规划

当我们使用`yiic`命令行工具最初创建 TrackStar 应用程序时，我们注意到基本的登录功能已经为我们自动创建。登录页面允许两个用户名/密码凭据组合，`demo/demo`和`admin/admin`。您可能还记得我们必须登录到应用程序中，以便在前两章中对项目和问题实体执行一些 CRUD 操作。

这个基本的身份验证骨架代码提供了一个很好的开始，但我们需要做一些改变，以支持任意数量的用户。我们还需要向应用程序添加用户 CRUD 功能，以便我们可以管理这些多个用户。本章将重点介绍扩展身份验证模型以使用`tbl_user`数据库表，并添加所需功能以允许基本用户数据管理。

为了实现上述目标，我们需要处理以下事项：

+   创建将包含允许我们执行以下功能的控制器类：

+   创建新用户

+   从数据库中检索现有用户的列表

+   更新/编辑现有用户

+   删除现有用户

+   创建视图文件和表示层逻辑，将：

+   显示表单以允许创建新用户

+   显示所有现有用户的列表

+   显示表单以允许编辑现有用户

+   添加删除按钮，以便我们可以删除用户

+   调整创建新用户表单，以便外部用户可以使用自注册流程

+   修改身份验证过程，以使用数据库验证登录凭据。

# 用户 CRUD

由于我们正在构建一个基于用户的 Web 应用程序，我们必须有一种方法来添加和管理用户。我们在第五章 *管理问题*中向数据库添加了`tbl_user`表。您可能还记得我们留给读者的练习是创建相关的 AR 模型类。如果您正在跟着做，并且没有创建必要的用户模型类，现在需要这样做。

以下是使用 Gii 代码创建工具创建模型类的简要提醒：

1.  通过`http://localhost/trackstar/index.php?r=gii`导航到 Gii 工具，并选择**Model Generator**链接。

1.  将表前缀保留为`tbl_`。在**Table Name**字段中填写`tbl_user`，这将自动填充**Model Class**名称字段为**User**。

1.  填写表单后，单击**Preview**按钮，获取一个链接到弹出窗口，显示即将生成的所有代码。

1.  最后，单击**Generate**按钮，实际创建新的`User.php`模型类文件在`/protected/models/`目录中。

有了`User` AR 类，创建 CRUD 脚手架就变得很简单。我们以前使用过 Gii 工具做过这个。提醒一下，以下是必要的步骤：

1.  通过`http://localhost/trackstar/index.php?r=gii`导航到工具。

1.  从可用生成器列表中单击**Crud Generator**链接。

1.  在**Model Class**名称字段中键入`User`。相应的**Controller ID**将自动填充为**User**。

1.  然后，您将看到在生成之前预览每个文件的选项。单击**生成**按钮，它将在适当的位置生成所有相关的 CRUD 文件。

有了这个，我们可以在`http://localhost/trackstar/index.php?r=user/index`查看我们的用户列表页面。在上一章中，我们手动创建了一些用户，以便我们可以正确处理项目、问题和用户之间的关系。这就是为什么我们在这个页面上看到了一些用户。以下截图显示了我们如何显示这个页面：

![用户 CRUD](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_06_01.jpg)

我们还可以通过访问`http://localhost/trackstar/index.php?r=user/create`来查看新的**创建用户**表单。如果您当前未登录，您将首先被路由到登录页面，然后才能查看表单。因此，您可能需要使用`demo/demo`或`admin/admin`登录以查看此表单。

在我们首先在项目实体上，然后再次在问题上创建和使用 CRUD 操作功能后，我们现在非常熟悉这些功能最初是如何由 Gii 代码生成工具实现的。用于创建和更新的生成代码是一个很好的开始，但需要一些调整以满足特定的应用程序要求。我们刚刚为创建新用户生成的表单也不例外。它为在`tbl_user`表中定义的每个列都有一个输入表单字段。我们不希望将所有这些字段都暴露给用户输入。最后登录时间、创建时间和用户以及更新时间和用户的列应在提交表单后以编程方式设置。

## 更新我们的常见审计历史列

回到之前的章节，当我们介绍我们的**项目**和**问题**CRUD 功能时，我们还注意到我们的表单有比应该更多的输入字段。由于我们已经定义了所有的数据库表都有相同的创建和更新时间和用户列，我们的每个自动生成的输入表单都暴露了这些字段。在第四章中处理项目创建表单时，我们完全忽略了这些字段，*项目 CRUD*。然后，在第五章中，*管理问题*，我们采取了一步措施，从表单中删除了这些字段的显示，但我们从未添加逻辑来在添加新行时正确设置这些值。

让我们花一点时间添加这个所需的逻辑。由于我们的实体表`tbl_project`、`tbl_issue`和`tbl_user`都定义了相同的列，我们可以将我们的逻辑添加到一个公共基类中，然后让每个单独的 AR 类从这个新的基类扩展。这是将相同功能应用于相同类型实体的常见方法。然而，Yii 组件——即`CComponent`的任何实例或`CComponent`的派生类，这通常是 Yii 应用程序中大多数类的情况——为您提供了另一种，可能更灵活的选择。

### 组件行为

Yii 中的行为是实现`IBehavior`接口的类，其方法可以通过附加到组件而不是显式扩展类来扩展组件的功能。行为可以附加到多个组件，组件可以附加多个行为。跨组件重用行为使它们非常灵活，通过能够将多个行为附加到同一个组件，我们能够为我们的 Yii 组件类实现一种*多重继承*。

我们将使用这种方法为我们的模型类添加所需的功能。我们采取这种方法的原因是，我们的其他模型类，`Issue`和`Project`，也需要相同的逻辑。与其在每个 AR 模型类中重复代码，将功能放在行为中，然后将行为附加到模型类中，将允许我们在一个地方为每个 AR 模型类正确设置这些字段。

为了让组件使用行为的方法，行为必须附加到组件上。这只需要在组件上调用`attachBehavior()`方法就可以了：

```php
$component->attachBehavior($name, $behavior);
```

在之前的代码中，`$name`是组件内行为的唯一标识符。一旦附加，组件就可以调用行为类中定义的方法：

```php
$component->myBehaviorMethod();
```

在之前的代码中，`myBehaviorMethod()`在`$behavior`类中被定义，但可以像在`$component`类中定义一样调用。

对于模型类，我们可以在`behaviors()`方法中添加我们想要的行为，这是我们将采取的方法。现在我们只需要创建一个要附加的行为。

事实上，Yii 框架打包的 Zii 扩展库已经有一个现成的行为，可以更新我们每个基础表上的日期时间列`create_time`和`update_time`。这个行为叫做`CTimestampBehavior`。所以，让我们开始使用这个行为。

让我们从我们的`User`模型类开始。将以下方法添加到`protected/models/User.php`中：

```php
public function behaviors() 
{
  return array(
     'CTimestampBehavior' => array(
       'class' => 'zii.behaviors.CTimestampBehavior',
       'createAttribute' => 'create_time',
       'updateAttribute' => 'update_time',
      'setUpdateOnCreate' => true,
    ),
   );
}
```

在这里，我们将 Zii 扩展库的`CTimestampBehavior`附加到我们的`User`模型类上。我们已经指定了创建时间和更新时间属性，并且还配置了行为，在创建新记录时设置更新时间。有了这个设置，我们可以试一下。创建一个新用户，你会看到`create_time`和`update_time`记录被自动插入。很酷，对吧？

![组件行为](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_06_07.jpg)

这很棒，但我们需要在其他模型类中重复这个过程。我们可以在每个模型类中复制`behaviors()`方法，并且在添加更多模型类时继续这样做。或者，我们可以将其放在一个通用的基类中，并让我们的每个模型类扩展这个新的基类。这样，我们只需要定义一次`behaviors()`方法。

当我们保存和更新记录时，我们还需要插入我们的`create_user_id`和`update_user_id`列。我们可以以多种方式处理这个问题。由于一个组件可以附加多个行为，我们可以创建一个类似于`CTimestampBehavior`的新行为，用于更新创建和更新用户 ID 列。或者，我们可以简单地扩展`CTimestampBehavior`，并在这个子类中添加额外的功能。或者我们可以直接利用模型的`beforeSave`事件，并在那里设置我们需要的字段。在现实世界的应用中，扩展现有的行为以添加这个额外的功能可能是最合理的方法；然而，为了演示另一种方法，让我们直接利用活动记录的`beforeSave`事件，并在一个通用的基类中进行这个操作，所有我们的 AR 模型类都可以扩展这个基类。这样，当构建自己的 Yii 应用程序时，你将有机会接触到几种不同的方法，并有更多的选择。

所以，我们需要为我们的 AR 模型类创建一个新的基类。我们还将使这个新类成为`abstract`，因为它不应该直接实例化。首先，去掉`User` AR 类中的`behaviors()`方法，因为我们将把这个方法放在我们的基类中。然后创建一个新文件，`protected/models/TrackStarActiveRecord.php`，并添加以下代码：

```php
<?php
abstract class TrackStarActiveRecord extends CActiveRecord
{
   /**
   * Prepares create_user_id and update_user_id attributes before saving.
   */

  protected function beforeSave()
  {

    if(null !== Yii::app()->user)
      $id=Yii::app()->user->id;
    else
      $id=1;

    if($this->isNewRecord)
      $this->create_user_id=$id;

    $this->update_user_id=$id;

    return parent::beforeSave();
  }

  /**
   * Attaches the timestamp behavior to update our create and update times
   */
  public function behaviors() 
  {
    return array(
       'CTimestampBehavior' => array(
         'class' => 'zii.behaviors.CTimestampBehavior',
         'createAttribute' => 'create_time',
         'updateAttribute' => 'update_time',
        'setUpdateOnCreate' => true,
      ),
     );
  }

}
```

在这里，正如讨论的那样，我们正在重写`CActiveRecord::beforeSave()`方法。这是`CActiveRecord`公开的许多事件之一，允许定制其流程工作流。有两种方法可以让我们进入记录保存工作流程，并在活动记录保存之前或之后执行任何必要的逻辑：`beforeSave()`和`afterSave()`。在这种情况下，我们决定在保存活动记录之前明确设置我们的创建和更新用户字段，即在写入数据库之前。

我们通过使用属性`$this->isNewRecord`来确定我们是在处理新记录（即插入）还是现有记录（即更新），并相应地设置我们的字段。然后，我们确保调用父实现，通过返回`parent::beforeSave()`来确保它有机会做所有需要做的事情。我们对`Yii::app()->user`进行了`NULL`检查，以处理可能在 Web 应用程序上下文之外使用这个模型类的情况，例如在 Yii 控制台应用程序中（在后面的章节中介绍）。如果我们没有有效的用户，我们只是默认使用第一个用户，`id = 1`，我们可以设置为超级用户。

另外，正如讨论的那样，我们已经将`behaviors()`方法移到了这个基类中，这样所有扩展它的 AR 模型类都将具有这个行为附加。

为了尝试这个，我们现在需要修改现有的三个 AR 类`Project.php`，`User.php`和`Issue.php`，使其扩展自我们的新抽象类，而不是直接扩展自`CActiveRecord`。因此，例如，而不是以下内容：

```php
class User extends CActiveRecord
{
…}
```

我们需要有：

```php
class User extends TrackStarActiveRecord
{ 
…}
```

我们需要对我们的其他模型类进行类似的更改。

现在，如果我们添加另一个新用户，我们应该看到我们的所有四个审计历史列都填充了时间戳和用户 ID。

现在，这些更改已经就位，我们应该从创建新项目、问题和用户的每个表单中删除这些字段（我们已经在上一章中从问题表单中删除了它们）。这些表单字段的 HTML 位于`protected/views/project/_form.php`，`protected/views/issue/_form.php`和`protected/views/user/_form.php`文件中。我们需要从这些文件中删除的行如下所示：

```php
<div class="row">
    <?php echo $form->labelEx($model,'create_time'); ?>
    <?php echo $form->textField($model,'create_time'); ?>
    <?php echo $form->error($model,'create_time'); ?>
  </div>

  <div class="row">
    <?php echo $form->labelEx($model,'create_user_id'); ?>
    <?php echo $form->textField($model,'create_user_id'); ?>
    <?php echo $form->error($model,'create_user_id'); ?>
  </div>

  <div class="row">
    <?php echo $form->labelEx($model,'update_time'); ?>
    <?php echo $form->textField($model,'update_time'); ?>
    <?php echo $form->error($model,'update_time'); ?>
  </div>

  <div class="row">
    <?php echo $form->labelEx($model,'update_user_id'); ?>
    <?php echo $form->textField($model,'update_user_id'); ?>
    <?php echo $form->error($model,'update_user_id'); ?>
  </div>
```

并且从用户创建表单`protected/views/user/_form.php`中，我们也可以删除最后登录时间字段：

```php
<div class="row">
    <?php echo $form->labelEx($model,'last_login_time'); ?>
    <?php echo $form->textField($model,'last_login_time'); ?>
    <?php echo $form->error($model,'last_login_time'); ?>
  </div>
```

由于我们正在从表单输入中删除这些字段，我们还应该删除相关规则方法中为这些字段定义的验证规则。这些验证规则旨在确保用户提交的数据有效且格式正确。删除规则还可以防止它们成为当我们获取所有提交的查询字符串或 POST 变量并将它们的值分配给我们的 AR 模型属性时的批量分配的一部分。例如，在 AR 模型的创建和更新控制器操作中，我们看到以下行：

```php
$model->attributes=$_POST['User'];
```

这是对从提交的表单字段中的所有模型属性进行批量分配。作为一项额外的安全措施，这仅适用于为其分配了验证规则的属性。您可以使用`CSafeValidator`来标记模型属性，以便将其作为这种批量分配的安全属性。

由于这些字段不会由用户填写，并且我们不需要它们被大规模分配，我们可以删除这些规则。

好的，让我们把它们删除。打开`protected/models/User.php`，在`rules()`方法中删除以下两条规则：

```php
array('create_user_id, update_user_id', 'numerical', 'integerOnly'=>true),
array('last_login_time, create_time, update_time', 'safe'),
```

项目和问题 AR 类定义了类似的规则，但并非完全相同。在删除这些规则时，请确保保留仍适用于用户输入字段的规则。

上面删除`last_login_time`属性的规则是有意的。我们也应该将其从用户输入字段中删除。这个字段需要在成功登录后自动更新。由于我们已经打开了视图文件并删除了其他字段，我们决定现在也删除这个字段。但是，在我们进行其他一些更改并涵盖其他一些主题之后，我们将等待添加必要的应用程序逻辑。

实际上，当我们还在`User`类的验证规则方法中时，我们应该做出另一个改变。我们希望确保每个用户的电子邮件和用户名都是唯一的。我们应该在提交表单时验证这一要求。此外，我们还应该验证提交的电子邮件数据是否符合标准的电子邮件格式。您可能还记得在第四章中，我们介绍了 Yii 的内置验证器，其中有两个非常适合我们的需求。我们将使用`CEmailValidator`和`CUniqueValidator`类来满足我们的验证需求。我们可以通过在`rules()`方法中添加以下两行代码来快速添加这些规则：

```php
array('email, username', 'unique'),
array('email', 'email'),
```

整个`User::rules()`方法现在应该如下所示：

```php
public function rules()
  {
    // NOTE: you should only define rules for those attributes that
    // will receive user inputs.
    return array(
      array('email', 'required'),
array('email, username, password', 'length', 'max'=>255,
array('email, username', 'unique'),
array('email', 'email'),
      // The following rule is used by search().
      // Please remove those attributes that should not be searched.
      array('id, email, username, password, last_login_time, create_time, create_user_id, update_time, update_user_id', 'safe', 'on'=>'search'),
    );
  }
```

上面规则中的*unique*声明是一个别名，指的是 Yii 的内置验证器`CUniqueValidator`。这验证了模型类属性在底层数据库表中的唯一性。通过添加这个验证规则，当尝试输入已经存在于数据库中的电子邮件和/或用户名时，我们将收到一个错误。此外，通过添加电子邮件验证，当电子邮件表单字段中的值不是正确的电子邮件格式时，我们将收到一个错误。

在上一章中创建`tbl_user`表时，我们添加了两个测试用户，以便我们有一些数据可以使用。这两个用户中的第一个用户的电子邮件地址是`test1@notanaddress.com`。尝试使用相同的电子邮件添加另一个用户。以下截图显示了尝试后收到的错误消息以及错误字段的高亮显示：

![组件行为](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_06_02.jpg)

提交一个不符合有效电子邮件格式的值也会产生错误消息。

## 添加密码确认字段

除了刚刚做的更改之外，我们还应该添加一个新字段，强制用户确认他们输入的密码。这是用户注册表单上的标准做法，有助于用户在输入这一重要信息时不出错。幸运的是，Yii 还带有另一个内置的验证器`CCompareValidator`，它正是你所想的那样。它比较两个属性的值，如果它们不相等，则返回错误。

为了利用这个内置的验证，我们需要在我们的模型类中添加一个新的属性。在`User`模型 AR 类的顶部添加以下属性：

```php
public $password_repeat;
```

我们通过在要比较的属性名称后附加`_repeat`来命名此属性。比较验证器允许您指定任意两个属性进行比较，或将属性与常量值进行比较。如果在声明比较规则时未指定比较属性或值，它将默认查找以与要比较的属性相同的名称开头的属性，并在末尾附加`_repeat`。这就是我们以这种方式命名属性的原因。现在我们可以在`User::rules()`方法中添加一个简单的验证规则，如下所示：

```php
array('password', 'compare'),
```

如果不使用`_repeat`约定，您需要指定要执行比较的属性。例如，如果我们想要将`$password`属性与名为`$confirmPassword`的属性进行比较，我们可以使用：

```php
array('password', 'compare', 'compareAttribute'=>'confirmPassword'),
```

由于我们已经明确将`$password_repeat`属性添加到用户 AR 类中，并且没有为其定义验证规则，因此当调用`setAttributes()`方法时，我们还需要告诉模型类允许以批量方式设置此字段。如前所述，我们通过将新属性明确添加到`User`模型类的*safe*属性列表中来实现这一点。要做到这一点，请将以下内容添加到`User::rules()`数组中：

```php
array('password_repeat', 'safe'),
```

让我们对验证规则做出一次更改。我们当前在用户表单上拥有的所有字段都应该是必填的。目前，我们的必填规则只适用于`email`字段。在我们对`User::rules()`方法进行更改时，让我们也将用户名和密码添加到此列表中：

```php
array('email, username, password, password_repeat', 'required'),
```

### 注意

有关验证规则的更多信息，请参见：[`www.yiiframework.com/doc/guide/1.1/en/form.model#declaring-validation-rules`](http://www.yiiframework.com/doc/guide/1.1/en/form.model#declaring-validation-rules)

好的，现在我们所有的规则都已设置。但是，我们仍然需要向表单添加密码确认字段。现在让我们来做这件事。

要添加此字段，请打开`protected/views/user/_form.php`，并在密码字段下方添加以下代码块：

```php
<div class="row">
    <?php echo $form->labelEx($model,'password_repeat'); ?>
    <?php echo $form->passwordField($model,'password_repeat',array('size'=>60,'maxlength'=>255)); ?>
    <?php echo $form->error($model,'password_repeat'); ?>
  </div>
```

在所有这些表单更改就位后，**创建用户**表单应如下截图所示：

![添加密码确认字段](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_06_03.jpg)

现在，如果我们尝试使用**密码**和**密码重复**字段中的不同值提交表单，我们将会收到如下截图所示的错误：

![添加密码确认字段](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_06_04.jpg)

## 对密码进行哈希处理

在我们离开新用户创建过程之前，我们应该做的最后一个更改是在将用户的密码存储到数据库之前创建其哈希版本。在将敏感用户信息添加到持久存储之前应用单向哈希算法是一种非常常见的做法。

我们将利用`CActiveRecord`的另一种方法来将此逻辑添加到`User.php` AR 类中，该方法允许我们自定义默认的活动记录工作流程。这次我们将重写`afterValidate()`方法，并在验证所有输入字段但在保存记录之前对密码应用基本的单向哈希。

### 注意

与我们在设置创建和更新时间戳时使用`CActiveRecord::beforeSave()`方法类似，这里我们正在重写`CActiveRecord::beforeValidate()`方法。这是`CActiveRecord`公开的许多事件之一，允许自定义其流程工作流程。快速提醒一下，如果在调用 AR 类的`save()`方法时没有显式发送`false`作为参数，验证过程将被触发。该过程执行 AR 类中`rules()`方法中指定的验证。有两种公开的方法允许我们进入验证工作流程并在验证执行之前或之后执行任何必要的逻辑，即`beforeValidate()`和`afterValidate()`。在这种情况下，我们决定在执行验证后立即对密码进行哈希处理。

打开`User` AR 类，并在类底部添加以下内容：

```php
    /**
   * apply a hash on the password before we store it in the database
   */
  protected function afterValidate()
  {   
    parent::afterValidate();
  if(!$this->hasErrors())
      $this->password = $this->hashPassword($this->password);
  }

  /**
   * Generates the password hash.
   * @param string password
     * @return string hash
   */
    public function hashPassword($password)
  {
    return md5($password);
  }
```

### 注意

我们在上一章中提到过这一点，但值得再次提及。我们在这里使用单向 MD5 哈希算法是因为它易于使用，并且在 MySQL 和 PHP 的 5.x 版本中广泛可用。然而，现在已经知道 MD5 在安全方面作为单向哈希算法是“破解”的，因此不建议在生产环境中使用此哈希算法。请考虑在真正的生产应用程序中使用 Bcrypt。以下是一些提供有关 Bcrypt 更多信息的网址：

+   [`en.wikipedia.org/wiki/Bcrypt`](http://en.wikipedia.org/wiki/Bcrypt)

+   [`php.net/manual/en/function.crypt.php`](http://php.net/manual/en/function.crypt.php)

+   [`www.openwall.com/phpass/`](http://www.openwall.com/phpass/)

有了这个配置，它将在所有其他属性验证成功通过之后对密码进行哈希处理。

### 注意

这种方法对于全新的记录来说效果很好，但是对于更新来说，如果用户没有更新他/她的密码信息，就有可能对已经进行过哈希处理的值再次进行哈希处理。我们可以用多种方式来处理这个问题，但是为了简单起见，我们需要确保每次用户想要更新他们的用户数据时，我们都要求他们提供有效的密码。

现在我们有能力向我们的应用程序添加新用户。由于我们最初使用 Gii 工具的**Crud Generator**链接创建了这个表单，我们还为用户拥有了读取、更新和删除功能。通过添加一些新用户，查看他们的列表，更新一些信息，然后删除一些条目来测试一下，确保一切都按预期工作。（请记住，您需要以`admin`身份登录，而不是`demo`，才能执行删除操作。）

# 使用数据库对用户进行认证

正如我们所知，通过使用`yiic`命令创建我们的新应用程序，为我们创建了一个基本的登录表单和用户认证过程。这种认证方案非常简单。它会检查输入表单的用户名/密码值，如果它们是`demo/demo`或`admin/admin`，就会通过，否则就会失败。显然，这并不是一个永久的解决方案，而是一个构建的基础。我们将通过改变认证过程来使用我们已经作为模型的一部分拥有的`tbl_user`数据库表来构建。但在我们开始改变默认实现之前，让我们更仔细地看一下 Yii 是如何实现认证模型的。

## 介绍 Yii 认证模型

Yii 认证框架的核心是一个名为**user**的应用组件，通常情况下，它是一个实现了`IWebUser`接口的对象。我们默认实现所使用的具体类是框架类`CWebUser`。这个用户组件封装了应用程序当前用户的所有身份信息。这个组件在我们使用`yiic`工具创建应用程序时，作为自动生成的应用程序代码的一部分为我们配置好了。配置可以在`protected/config/main.php`文件的`components`数组元素下看到：

```php
'user'=>array(
  // enable cookie-based authentication
  'allowAutoLogin'=>true,
),
```

由于它被配置为一个应用程序组件，名称为`'user'`，我们可以在整个应用程序中的任何地方使用`Yii::app()->user`来访问它。

我们还注意到类属性`allowAutoLogin`也在这里设置了。这个属性默认值为`false`，但将其设置为`true`可以使用户信息存储在持久性浏览器 cookie 中。然后这些数据将用于在后续访问时自动对用户进行身份验证。这将允许我们在登录表单上有一个**记住我**复选框，这样用户可以选择的话，在后续访问网站时可以自动登录应用程序。

Yii 认证框架定义了一个单独的实体来容纳实际的认证逻辑。这被称为**身份类**，通常可以是任何实现了`IUserIdentity`接口的类。这个类的主要作用之一是封装认证逻辑，以便轻松地允许不同的实现。根据应用程序的要求，我们可能需要验证用户名和密码与存储在数据库中的值匹配，或者允许用户使用他们的 OpenID 凭据登录，或者集成现有的 LDAP 方法。将特定于认证方法的逻辑与应用程序登录过程的其余部分分离，使我们能够轻松地在这些实现之间切换。身份类提供了这种分离。

当我们最初创建应用程序时，一个用户身份类文件，即 `protected/components/UserIdentity.php`，是为我们生成的。它扩展了 Yii 框架类 `CUserIdentity`，这是一个使用用户名和密码的身份验证实现的基类。让我们更仔细地看一下为这个类生成的代码：

```php
<?php
/**
 * UserIdentity represents the data needed to identity a user.
 * It contains the authentication method that checks if the provided
 * data can identify the user.
 */
class UserIdentity extends CUserIdentity
{
  /**
   * Authenticates a user.
   * The example implementation makes sure if the username and password
   * are both 'demo'.
   * In practical applications, this should be changed to authenticate
   * against some persistent user identity storage (e.g. database).
   * @return boolean whether authentication succeeds.
   */
  public function authenticate()
  {
    $users=array(
      // username => password
      'demo'=>'demo',
      'admin'=>'admin',
    );
    if(!isset($users[$this->username]))
      $this->errorCode=self::ERROR_USERNAME_INVALID;
    else if($users[$this->username]!==$this->password)
      $this->errorCode=self::ERROR_PASSWORD_INVALID;
    else
      $this->errorCode=self::ERROR_NONE;
    return !$this->errorCode;
  }
}
```

定义身份类的大部分工作是实现 `authenticate()` 方法。这是我们放置特定于身份验证方法的代码的地方。这个实现简单地使用硬编码的用户名/密码值 `demo/demo` 和 `admin/admin`。它检查这些值是否与用户名和密码类属性（在父类 `CUserIdentity` 中定义的属性）匹配，如果不匹配，它将设置并返回适当的错误代码。

为了更好地理解这些部分如何适应整个端到端的身份验证过程，让我们从登录表单开始逐步解释逻辑。如果我们导航到登录页面，`http://localhost/trackstar/index.php?r=site/login`，我们会看到一个简单的表单，允许输入用户名、密码，以及我们之前讨论过的**记住我下次**功能的可选复选框。提交这个表单会调用 `SiteController::actionLogin()` 方法中包含的逻辑。以下序列图描述了在成功登录时从提交表单开始发生的类交互。

![引入 Yii 身份验证模型](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_06_05.jpg)

这个过程从将表单模型类 `LoginForm` 上的类属性设置为提交的表单值开始。然后调用 `LoginForm->validate()` 方法，根据 `rules()` 方法中定义的规则验证这些属性值。这个方法定义如下：

```php
public function rules()
{
  return array(
    // username and password are required
    array('username, password', 'required'),
    // rememberMe needs to be a boolean
    array('rememberMe', 'boolean'),
    // password needs to be authenticated
    array('password', 'authenticate'),
  );
}
```

最后一个规则规定，密码属性要使用自定义方法 `authenticate()` 进行验证，这个方法也在 `LoginForm` 类中定义如下：

```php
/**
   * Authenticates the password.
   * This is the 'authenticate' validator as declared in rules().
   */
  public function authenticate($attribute,$params)
  {
    $this->_identity=new UserIdentity($this->username,$this->password);
    if(!$this->_identity->authenticate())
      $this->addError('password','Incorrect username or password.');
  }
```

继续按照序列图的顺序，`LoginForm` 中的密码验证调用了同一类中的 `authenticate()` 方法。该方法创建了一个正在使用的身份验证身份类的新实例，本例中是 `/protected/components/UserIdentity.php`，然后调用它的 `authenticate()` 方法。这个方法，`UserIdentity::authenticate()` 如下：

```php
/**
   * Authenticates a user.
   * The example implementation makes sure if the username and password
   * are both 'demo'.
   * In practical applications, this should be changed to authenticate
   * against some persistent user identity storage (e.g. database).
   * @return boolean whether authentication succeeds.
   */
  public function authenticate()
  {
    $users=array(
      // username => password
      'demo'=>'demo',
      'admin'=>'admin',
    );
    if(!isset($users[$this->username]))
      $this->errorCode=self::ERROR_USERNAME_INVALID;
    else if($users[$this->username]!==$this->password)
      $this->errorCode=self::ERROR_PASSWORD_INVALID;
    else
      $this->errorCode=self::ERROR_NONE;
    return !$this->errorCode;
  }
```

这是为了使用用户名和密码进行身份验证。在这个实现中，只要用户名/密码组合是 `demo/demo` 或 `admin/admin`，这个方法就会返回 `true`。由于我们正在进行成功的登录，身份验证成功，然后 `SiteController` 调用 `LoginForm::login()` 方法，如下所示：

```php
/**
   * Logs in the user using the given username and password in the model.
   * @return boolean whether login is successful
   */
  public function login()
  {
    if($this->_identity===null)
    {
      $this->_identity=new UserIdentity($this->username,$this->password);
      $this->_identity->authenticate();
    }
    if($this->_identity->errorCode===UserIdentity::ERROR_NONE)
    {
      $duration=$this->rememberMe ? 3600*24*30 : 0; // 30 days
      Yii::app()->user->login($this->_identity,$duration);
      return true;
    }
    else
      return false;
  }
```

我们可以看到，这反过来调用了 `Yii::app()->user->login`（即 `CWebUser::login()`），传入 `CUserIdentity` 类实例以及要设置自动登录的 cookie 的持续时间。

默认情况下，Web 应用程序配置为使用 Yii 框架类 `CWebuser` 作为用户应用组件。它的 `login()` 方法接受一个身份类和一个可选的持续时间参数，用于设置浏览器 cookie 的生存时间。在前面的代码中，我们看到如果在提交表单时选中了**记住我**复选框，这个时间被设置为 `30 天`。如果你不传入一个持续时间，它会被设置为零。零值将导致根本不创建任何 cookie。

`CWebUser::login()` 方法获取身份类中包含的信息，并将其保存在持久存储中，以供用户会话期间使用。默认情况下，这个存储是 PHP 会话存储。

完成所有这些后，由我们的控制器类最初调用的`LoginForm`上的`login()`方法返回`true`，表示成功登录。然后，控制器类将重定向到`Yii::app()->user->returnUrl`中的 URL 值。如果您希望确保用户被重定向回其先前的页面，即在他们决定（或被迫）登录之前在应用程序中的任何位置，可以在应用程序的某些页面上设置此值。此值默认为应用程序入口 URL。

### 更改身份验证实现

现在我们了解了整个身份验证过程，我们可以很容易地看到我们需要在哪里进行更改，以使用我们的`tbl_user`表来验证通过登录表单提交的用户名和密码凭据。我们可以简单地修改用户身份类中的`authenticate()`方法，以验证是否存在与提供的用户名和密码值匹配的行。由于目前在我们的`UserIdentity.php`类中除了 authenticate 方法之外没有其他内容，让我们完全用以下代码替换此文件的内容：

```php
<?php

/**
 * UserIdentity represents the data needed to identity a user.
 * It contains the authentication method that checks if the provided
 * data can identity the user.
 */

class UserIdentity extends CUserIdentity
{
  private $_id;

  public function authenticate()
  {
    $user=User::model()->find('LOWER(username)=?',array(strtolower($this->username)));
    if($user===null)
      $this->errorCode=self::ERROR_USERNAME_INVALID;
    else if(!$user->validatePassword($this->password))
      $this->errorCode=self::ERROR_PASSWORD_INVALID;
    else
    {
      $this->_id=$user->id;
      $this->username=$user->username;
$this->setState('lastLogin', date("m/d/y g:i A", strtotime($user->last_login_time)));
      $user->saveAttributes(array(
        'last_login_time'=>date("Y-m-d H:i:s", time()),
      ));
      $this->errorCode=self::ERROR_NONE;
    }
    return $this->errorCode==self::ERROR_NONE;
  }

  public function getId()
  {
    return $this->_id;
  }
}
```

并且，由于我们将让我们的`User`模型类执行实际的密码验证，我们还需要向我们的`User`模型类添加以下方法：

```php
/**
   * Checks if the given password is correct.
   * @param string the password to be validated
   * @return boolean whether the password is valid
   */
  public function validatePassword($password)
  {
    return $this->hashPassword($password)===$this->password;
  }
```

这个新代码有一些需要指出的地方。首先，它现在尝试通过创建一个新的`User`模型 AR 类实例来从`tbl_user`表中检索一行，其中用户名与`UserIdentity`类的属性值相同（请记住，这是设置为登录表单的值）。由于在创建新用户时我们强制用户名的唯一性，这应该最多找到一个匹配的行。如果找不到匹配的行，将设置错误消息以指示用户名不正确。如果找到匹配的行，它通过调用我们的新`User::validatePassword()`方法来比较密码。如果密码未通过验证，将设置错误消息以指示密码不正确。

如果身份验证成功，在方法返回之前还会发生一些其他事情。首先，我们在`UserIdentity`类上设置了一个新的属性，用于用户 ID。父类中的默认实现是返回 ID 的用户名。由于我们使用数据库，并且将数字主键作为我们唯一的用户标识符，我们希望确保在请求用户 ID 时设置和返回此值。例如，当执行代码`Yii::app()->user->id`时，我们希望确保从数据库返回唯一 ID，而不是用户名。

### 扩展用户属性

这里发生的第二件事是在用户身份上设置一个属性，该属性是从数据库返回的最后登录时间，然后还更新数据库中的`last_login_time`字段为当前时间。执行此操作的特定代码如下：

```php
$this->setState('lastLogin', date("m/d/y g:i A", strtotime($user->last_login_time)));
$user->saveAttributes(array(
  'last_login_time'=>date("Y-m-d H:i:s", time()),
));
```

用户应用组件`CWebUser`从身份类中定义的显式 ID 和名称属性派生其用户属性，然后从称为`identity states`的数组中设置的`name=>value`对中派生。这些是可以在用户会话期间持久存在的额外用户值。作为这一点的例子，我们将名为`lastLogin`的属性设置为数据库中`last_login_time`字段的值。这样，在应用程序的任何地方，都可以通过以下方式访问此属性：

```php
Yii::app()->user->lastLogin;
```

我们在存储最后登录时间与 ID 时采取不同的方法的原因是*ID*恰好是`CUserIdentity`类上明确定义的属性。因此，除了*name*和*ID*之外，所有需要在会话期间持久存在的其他用户属性都可以以类似的方式设置。

### 注意

当启用基于 cookie 的身份验证（通过将`CWebUser::allowAutoLogin`设置为`true`）时，持久信息将存储在 cookie 中。因此，您*不应*以与我们存储用户最后登录时间相同的方式存储敏感信息（例如您的密码）。

有了这些更改，现在您需要为数据库中`tbl_user`表中定义的用户提供正确的用户名和密码组合。当然，使用`demo/demo`或`admin/admin`将不再起作用。试一试。您应该能够以本章早些时候创建的任何一个用户的身份登录。如果您跟着做，并且拥有与我们相同的用户数据，那么用户名：`User One`，密码：`test1`应该可以登录。

### 注意

现在我们已经修改了登录流程，以便对数据库进行身份验证，我们将无法访问项目、问题或用户实体的删除功能。原因是已经设置了授权检查，以确保用户是管理员才能访问。目前，我们的数据库用户都没有配置为授权管理员。不用担心，授权是下一章的重点，所以我们很快就能再次访问该功能。

## 在主页上显示最后登录时间

现在我们正在更新数据库中的最后登录时间，并在登录时将其保存到持久会话存储中，让我们继续在成功登录后的欢迎屏幕上显示这个时间。这也将帮助我们确信一切都按预期工作。

打开负责显示主页的默认视图文件`protected/views/site/index.php`。在欢迎语句下面添加以下突出显示的代码行：

```php
<h1>Welcome to <i><?php echo CHtml::encode(Yii::app()->name); ?></i></h1>
<?php if(!Yii::app()->user->isGuest):?>
<p>
   You last logged in on <?php echo Yii::app()->user->lastLogin; ?>.  
</p>
<?php endif;?>
```

既然我们已经在这里，让我们继续删除所有其他自动生成的帮助文本，即我们刚刚添加的代码行下面的所有内容。保存并再次登录后，您应该看到类似以下截图的内容，显示欢迎消息，然后是格式化的时间，指示您上次成功登录的时间：

在主页上显示最后登录时间

# 总结

这一章是我们专注于用户管理、身份验证和授权的两章中的第一章。我们创建了管理应用程序用户的 CRUD 操作的能力，并在此过程中对新用户创建流程进行了许多调整。我们为所有活动记录类添加了一个新的基类，以便轻松管理存在于所有表上的审计历史表列。我们还更新了代码，以正确管理我们在数据库中存储的用户最后登录时间。在这样做的过程中，我们学习了如何利用`CActiveRecord`验证工作流来允许预验证/后验证和预保存/后保存处理。

然后，我们专注于理解 Yii 身份验证模型，以便增强它以满足我们应用程序的要求，以便用户凭据被验证为存储在数据库中的值。

现在我们已经涵盖了身份验证，我们可以将重点转向 Yii 身份验证和授权框架的第二部分，*授权*。这是下一章的重点。


# 第七章：用户访问控制

基于用户的 Web 应用程序，如我们的 TrackStar 应用程序，通常需要根据请求的发起者来控制对某些功能的访问。当我们谈论*用户访问控制*时，我们在高层次上指的是应用程序在进行请求时需要询问的一些问题。这些问题是：

+   谁在发起请求？

+   该用户是否有适当的权限来访问所请求的功能？

这些问题的答案有助于应用程序做出适当的响应。

在第六章中完成的工作为我们的应用程序提供了回答这些问题的能力。应用程序现在允许用户建立自己的身份验证凭据，并在用户登录时验证用户名和密码。成功登录后，应用程序确切地知道谁在发起后续的请求。

在本章中，我们将专注于帮助应用程序回答第二个问题。一旦用户提供了适当的身份识别，应用程序需要一种方法来确定他们是否也有权限执行所请求的操作。我们将通过利用 Yii 的用户访问控制功能来扩展我们的基本授权模型。Yii 提供了**简单的访问控制过滤器**以及更复杂的**基于角色的访问控制**（**RBAC**）实现，以帮助我们满足用户授权的要求。在实现 TrackStar 应用程序的用户访问要求时，我们将更仔细地研究这两者。

# 功能规划

当我们在第三章中首次介绍我们的 TrackStar 应用程序时，我们提到应用程序有两个高级用户状态，即匿名和已验证。这只是区分了已成功登录（已验证）和未登录（匿名）的用户。我们还介绍了已验证用户在项目内拥有不同角色的概念。在特定项目中，用户可以担任以下三种角色之一：

+   **项目所有者**对项目拥有*全部*的管理访问权限

+   **项目成员**具有*一些*管理访问权限，但与项目所有者相比，访问权限更有限

+   **项目读者**具有*只读*访问权限。这样的用户无法更改项目的内容

本章的重点是实施一种管理授予应用程序用户的访问控制的方法。我们需要一种方式来创建和管理我们的角色和权限，将它们分配给用户，并强制我们对每个用户角色想要的访问控制规则。

为了实现前面概述的目标，我们将在本章中专注于以下内容：

+   实施一种策略，强制用户在获得任何项目或问题相关功能的访问权限之前先登录

+   创建用户角色并将这些角色与特定的权限结构关联起来

+   实现将用户分配到角色（及其相关权限）的能力

+   确保我们的角色和权限结构存在于每个项目的基础上（即允许用户在不同项目中拥有不同的权限）

+   实现将用户关联到项目以及同时关联到项目内的角色的能力

+   在整个应用程序中实施必要的授权访问检查，以根据其权限适当地授予或拒绝应用程序用户的访问权限

幸运的是，Yii 自带了许多内置功能，帮助我们实现这些要求。所以，让我们开始吧。

# 访问控制过滤器

我们在第五章中首次介绍了*filters*，当我们在允许使用问题功能之前强制执行有效的项目上下文时。如果您还记得，我们在`IssueController`类中添加了一个类方法过滤器`filterProjectContext()`，以确保在对问题实体执行任何操作之前，我们有一个有效的项目上下文。Yii 提供了一种类似的方法，用于在控制器中逐个操作处理简单的访问控制。

Yii 框架提供了一个名为`accessControl`的过滤器。这个过滤器可以直接在控制器类中使用，以提供一个授权方案，用于验证用户是否可以访问特定的控制器操作。实际上，敏锐的读者会记得，当我们在第五章中实现`projectContext`过滤器时，我们注意到这个访问控制过滤器已经包含在我们的`IssueController`和`ProjectController`类的过滤器列表中，如下所示：

```php
/**
 * @return array action filters
 */
public function filters()
{
return array(
'accessControl', // perform access control for CRUD operations
);
}
```

这是使用 Gii CRUD 代码生成工具生成的自动生成代码中包含的。自动生成的代码还覆盖了`accessRules()`方法，这是必要的，以便使用访问控制过滤器。在这个方法中，您定义实际的授权规则。

我们的 CRUD 操作的默认实现设置为允许任何人查看现有问题和项目的列表。但是，它限制了创建和更新的访问权限，只允许经过身份验证的用户，并进一步将删除操作限制为特殊的*admin*用户。您可能还记得，当我们首次在项目上实现 CRUD 操作时，我们必须先登录才能创建新项目。在处理问题和用户时也是如此。控制这种授权和访问的机制正是这个访问控制过滤器。让我们更仔细地看一下`ProjectController.php`类文件中的这个实现。

`ProjectController`类中有两个与访问控制相关的方法：`filters()`和`accessRules()`。`filters()`方法配置过滤器。

```php
/**
 * @return array action filters
 */
public function filters()
{
return array(
'accessControl', // perform access control for CRUD operations
);
}
```

`accessRules()` 方法用于定义访问过滤器使用的授权规则，如下所示：

```php
/**
* Specifies the access control rules.
* This method is used by the 'accessControl' filter.
* @return array access control rules
*/
public function accessRules()
{
return array(
array('allow',  // allow all users to perform 'index' and 'view' actions
'actions'=>array('index','view'),
'users'=>array('*'),
),
array('allow', // allow authenticated user to perform 'create' and 'update' actions
'actions'=>array('create','update'),
'users'=>array('@'),
),
array('allow', // allow admin user to perform 'admin' and 'delete' actions
'actions'=>array('admin','delete'),
'users'=>array('admin'),
),
array('deny',  // deny all users
'users'=>array('*'),
),
);
}
```

`filters()` 方法对我们来说已经很熟悉了。在这里，我们指定控制器类中要使用的所有过滤器。在这种情况下，我们只有一个`accessControl`，它是 Yii 框架提供的一个过滤器。这个过滤器使用另一个方法`accessRules()`，它定义了驱动访问限制的规则。

在`accessRules()`方法中，指定了四条规则。每条规则都表示为一个数组。数组的第一个元素要么是*allow*，要么是*deny*。它们分别表示授予或拒绝访问。数组的其余部分由`name=>value`对组成，指定了规则的其余参数。

让我们先看一下之前定义的第一条规则：

```php
array('allow',  // allow all users to perform 'index' and 'view' actions
'actions'=>array('index','view'),
'users'=>array('*'),
),
```

这条规则允许任何用户执行`actionIndex()`和`actionView()`控制器操作。在`'users'`元素的值中使用的星号(`*`)是一种用于指定任何用户（匿名、经过身份验证或其他方式）的特殊字符。

现在让我们来看一下定义的第二条规则：

```php
array('allow', // allow authenticated user to perform 'create' and 'update' actions
'actions'=>array('create','update'),
'users'=>array('@'),
),
```

这允许任何经过身份验证的用户访问`actionCreate()`和`actionUpdate()`控制器操作。`@`特殊字符是一种指定任何经过身份验证的用户的方式。

第三条规则在以下代码片段中定义：

```php
array('allow', // allow admin user to perform 'admin' and 'delete' actions
'actions'=>array('admin','delete'),
'users'=>array('admin'),
),
```

这条规则指定了一个名为`admin`的特定用户被允许访问`actionAdmin()`和`actionDelete()`控制器操作。

最后，让我们更仔细地看一下第四条规则：

```php
array('deny',  // deny all users
'users'=>array('*'),
),
```

这条规则拒绝所有用户访问所有控制器操作。我们稍后会更详细地解释这一点。

可以使用多个上下文参数来定义访问规则。前面提到的规则正在指定动作和用户来创建规则上下文，但是还有其他几个参数可以使用。以下是其中一些：

+   **控制器**：指定规则应用的控制器 ID 数组。

+   **角色**：指定规则适用的授权项（角色、操作和权限）列表。这利用了我们将在下一节讨论的 RBAC 功能。

+   **IP 地址**：指定此规则适用的客户端 IP 地址列表。

+   **动词**：指定适用于此规则的 HTTP 请求类型（GET、POST 等）。

+   **表达式**：指定一个 PHP 表达式，其值指示是否应用规则。

+   **动作**：通过相应的动作 ID 指定动作方法，该规则应匹配到该动作。

+   **用户**：指定规则应用的用户。当前应用用户的名称属性用于匹配。这里也可以使用以下三个特殊字符：

1.  *****：任何用户

1.  **?**：匿名用户

1.  **@**：认证用户

如果没有指定用户，规则将适用于所有用户。

访问规则按照它们被指定的顺序逐一进行评估。与当前模式匹配的第一个规则确定授权结果。如果这个规则是一个允许规则，那么动作可以被执行；如果它是一个“拒绝”规则，那么动作就不能被执行；如果没有规则匹配上下文，动作仍然可以被执行。这就是前面提到的第四条规则的定义原因。如果我们没有在规则列表的末尾定义一个拒绝所有用户的规则，那么我们就无法实现我们期望的访问限制。举个例子，看看第二条规则。它指定认证用户可以访问 `actioncreate()` 和 `actionUpdate()` 动作。然而，它并没有规定匿名用户被拒绝访问。它对匿名用户什么也没说。前面提到的第四条规则确保了所有其他不匹配前三个具体规则的请求被拒绝访问。

有了这个设置，对匿名用户拒绝访问所有项目、问题和用户相关功能的应用程序进行更改就很容易。我们只需要将用户数组值的特殊字符`*`更改为`@`特殊字符。这将只允许认证用户访问 `actionIndex()` 和 `actionView()` 控制器动作。所有其他动作已经限制为认证用户。

现在，我们可以在我们的项目、问题和用户控制器类文件中每次进行三次更改。然而，我们有一个基础控制器类，每个类都是从中扩展出来的，即文件 `protected/components/Controller.php` 中的 `Controller` 类。因此，我们可以在这一个文件中添加我们的 CRUD 访问规则，然后从每个子类中删除它。我们还可以在定义规则时利用 `controllers` 上下文参数，以便它只适用于这三个控制器。

首先，让我们在我们的基础控制器类中添加必要的方法。打开 `protected/components/Controller.php` 并添加以下方法：

```php
/**
 * Specifies the access control rules.
 * This method is used by the 'accessControl' filter.
 * @return array access control rules
 */
public function accessRules()
{
return array(
array('allow',  // allow all users to perform 'index' and 'view' actions
**'controllers'=>array('issue','project','user'),**
'actions'=>array('index','view'),
**'users'=>array('@'),**
),
array('allow', // allow authenticated user to perform 'create' and 'update' actions
**'controllers'=>array('issue','project','user'),**
'actions'=>array('create','update'),
'users'=>array('@'),
),
array('allow', // allow admin user to perform 'admin' and 'delete' actions
**'controllers'=>array('issue','project','user'),**
'actions'=>array('admin','delete'),
'users'=>array('admin'),
),
array('deny',  // deny all users
**'controllers'=>array('issue','project','user'),**
'users'=>array('*'),
),
);
}
```

在前面代码片段中突出显示的代码显示了我们所做的更改。我们已经为每个规则添加了 `controllers` 参数，并将索引和查看动作的用户更改为只允许认证用户。

现在我们可以从每个指定的控制器中删除这个方法。打开 `ProjectController.php`、`IssueController.php` 和 `UserController.php` 三个文件，并删除它们各自的 `accessRules()` 方法。

做出这些更改后，应用程序将在访问我们的*项目*、*问题*或*用户*功能之前要求登录。我们仍然允许匿名用户访问`SiteController`类的操作方法，因为这是我们的登录操作所在的地方。显然，如果我们尚未登录，我们必须能够访问登录页面。

# 基于角色的访问控制

现在我们已经使用简单的访问控制过滤器限制了经过身份验证的用户的访问权限，我们需要转而关注满足应用程序更具体的访问控制需求。正如我们提到的，用户将在项目中扮演特定的角色。项目将有*所有者*类型的用户，可以被视为项目管理员。他们将被授予操纵项目的所有访问权限。项目还将有*成员*类型的用户，他们将被授予对项目功能的一些访问权限，但是比所有者能够执行的操作要少。最后，项目可以有*读者*类型的用户，他们只能查看与项目相关的内容，而不能以任何方式更改它。为了根据用户的角色实现这种类型的访问控制，我们转向 Yii 的基于角色的访问控制功能，也简称为 RBAC。

RBAC 是计算机系统安全中管理经过身份验证用户的访问权限的一种成熟方法。简而言之，RBAC 方法在应用程序中定义角色。还定义了执行某些操作的权限，然后将其与角色关联起来。然后将用户分配给一个角色，并通过角色关联获得为该角色定义的权限。对于对 RBAC 概念和方法感兴趣的读者，有大量的文档可供参考。例如维基百科，[`en.wikipedia.org/wiki/Role-based_access_control`](http://en.wikipedia.org/wiki/Role-based_access_control)。我们将专注于 Yii 对 RBAC 方法的具体实现。

Yii 对 RBAC 的实现简单、优雅且强大。在 Yii 中，RBAC 的基础是**授权项**的概念。授权项简单地是应用程序中执行操作的权限。这些权限可以被归类为*角色*、*任务*或*操作*，因此形成了一个权限层次结构。角色可以包括任务（或其他角色），任务可以包括操作（或其他任务），操作是最粒度的权限级别。

例如，在我们的 TrackStar 应用程序中，我们需要一个*所有者*类型的角色。因此，我们将创建一个*角色*类型的授权项，并将其命名为“所有者”。然后，这个角色可以包括诸如“用户管理”和“问题管理”之类的任务。这些任务可以进一步包括组成这些任务的原子操作。继续上面的例子，“用户管理”任务可以包括“创建新用户”、“编辑用户”和“删除用户”操作。这种层次结构允许继承这些权限，因此，以这个例子为例，如果一个用户被分配到所有者角色，他们就会继承对用户执行创建、编辑和删除操作的权限。

在 RBAC 中，通常你会将用户分配给一个或多个角色，用户会继承这些角色被分配的权限。在 Yii 中也是如此。然而，在 Yii 中，我们可以将用户与任何授权项关联，而不仅仅是*角色*类型的授权项。这使我们能够灵活地将特定权限与用户关联在任何粒度级别上。如果我们只想将“删除用户”操作授予特定用户，而不是给予他们所有者角色所具有的所有访问权限，我们可以简单地将用户与这个原子操作关联起来。这使得 Yii 中的 RBAC 非常灵活。

## 配置授权管理器

在我们可以建立授权层次结构，将用户分配给角色，并执行访问权限检查之前，我们需要配置授权管理器应用程序组件`authManager`。这个组件负责存储权限数据和管理权限之间的关系。它还提供了检查用户是否有权执行特定操作的方法。Yii 提供了两种类型的授权管理器`CPhpAuthManager`和`CDbAuthManager`。`CPhpAuthManager`使用 PHP 脚本文件来存储授权数据。`CDbAuthManager`，正如你可能已经猜到的，将授权数据存储在数据库中。`authManager`被配置为一个应用程序组件。配置授权管理器只需要简单地指定使用这两种类型中的哪一种，然后设置它的初始类属性值。

我们将使用数据库实现我们的应用程序。为了进行这个配置，打开主配置文件`protected/config/main.php`，并将以下内容添加到应用程序组件数组中：

```php
// application components
'components'=>array(
…
'authManager'=>array(
'class'=>'CDbAuthManager',
'connectionID'=>'db',
),
```

这建立了一个名为`authManager`的新应用程序组件，指定了类类型为`CDbAuthManager`，并将`connectionID`类属性设置为我们的数据库连接组件。现在我们可以在我们的应用程序的任何地方使用`Yii::app()->authManager`来访问它。

## 创建 RBAC 数据库表

如前所述，`CDbAuthManager`类使用数据库表来存储权限数据。它期望一个特定的模式。该模式在框架文件`YiiRoot/framework/web/auth/schema.sql`中被识别。这是一个简单而优雅的模式，由三个表`AuthItem`，`AuthItemChild`和`AuthAssignment`组成。

`AuthItem`表保存了定义角色、任务或操作的授权项的信息。`AuthItemChild`表存储了形成我们授权项层次结构的父/子关系。最后，`AuthAssignment`表是一个关联表，保存了用户和授权项之间的关联。

因此，我们需要将这个表结构添加到我们的数据库中。就像我们之前做过的那样，我们将使用数据库迁移来进行这些更改。从命令行，导航到 TrackStar 应用程序的`/protected`目录，并创建迁移：

```php
**$ cd /Webroot/trackstar/protected**
**$ ./yiic migrate create create_rbac_tables**

```

这将在`protected/migrations/`目录下创建一个根据迁移文件命名约定命名的新迁移文件（例如，`m120619_015239_create_rbac_tables.php`）。实现`up()`和`down()`迁移方法如下：

```php
public function up()
{
//create the auth item table
$this->createTable('tbl_auth_item', array(
'name' =>'varchar(64) NOT NULL',
'type' =>'integer NOT NULL',
'description' =>'text',
'bizrule' =>'text',
'data' =>'text',
'PRIMARY KEY (`name`)',
), 'ENGINE=InnoDB');

//create the auth item child table
$this->createTable('tbl_auth_item_child', array(
'parent' =>'varchar(64) NOT NULL',
'child' =>'varchar(64) NOT NULL',
'PRIMARY KEY (`parent`,`child`)',
), 'ENGINE=InnoDB');

//the tbl_auth_item_child.parent is a reference to tbl_auth_item.name
$this->addForeignKey("fk_auth_item_child_parent", "tbl_auth_item_child", "parent", "tbl_auth_item", "name", "CASCADE", "CASCADE");

//the tbl_auth_item_child.child is a reference to tbl_auth_item.name
$this->addForeignKey("fk_auth_item_child_child", "tbl_auth_item_child", "child", "tbl_auth_item", "name", "CASCADE", "CASCADE");

//create the auth assignment table
$this->createTable('tbl_auth_assignment', array(
'itemname' =>'varchar(64) NOT NULL',
'userid' =>'int(11) NOT NULL',
'bizrule' =>'text',
'data' =>'text',
'PRIMARY KEY (`itemname`,`userid`)',
), 'ENGINE=InnoDB');

//the tbl_auth_assignment.itemname is a reference 
//to tbl_auth_item.name
$this->addForeignKey(
"fk_auth_assignment_itemname", 
"tbl_auth_assignment", 
"itemname", 
"tbl_auth_item", 
"name", 
"CASCADE", 
"CASCADE"
);

//the tbl_auth_assignment.userid is a reference 
//to tbl_user.id
$this->addForeignKey(
"fk_auth_assignment_userid", 
"tbl_auth_assignment", 
"userid", 
"tbl_user", 
"id", 
"CASCADE", 
"CASCADE"
);
}

public function down()
{
$this->truncateTable('tbl_auth_assignment');
$this->truncateTable('tbl_auth_item_child');
$this->truncateTable('tbl_auth_item');
$this->dropTable('tbl_auth_assignment');
$this->dropTable('tbl_auth_item_child');
$this->dropTable('tbl_auth_item');
}
```

保存这些更改后，运行迁移以创建所需的结构：

```php
**$ ./yiic migrate**

```

一旦必要的结构被创建，你会在屏幕上看到一个`成功迁移`的消息。

由于我们遵循了数据库表命名约定，我们需要修改我们的`authManager`组件配置，以指定我们特定的表名。打开`/protected/config/main.php`，并将表名规范添加到`authManager`组件中：

```php
// application components
'components'=>array(
…
'authManager'=>array(
'class'=>'CDbAuthManager',
'connectionID'=>'db',
'itemTable' =>'tbl_auth_item',
'itemChildTable' =>'tbl_auth_item_child',
'assignmentTable' =>'tbl_auth_assignment',
),
```

现在授权管理器组件将确切地知道我们希望它使用哪些表来管理我们的授权结构。

### 注意

如果你需要关于如何使用 Yii 数据库迁移的提醒，请参考第四章，*项目 CRUD*，这个概念是在那里首次介绍的。

## 创建 RBAC 授权层次结构

在我们的`trackstar`数据库中添加了这些表之后，我们需要用我们的角色和权限填充它们。我们将使用`authmanager`组件提供的 API 来做到这一点。为了保持简单，我们只会定义角色和基本操作。我们现在不会设置任何正式的 RBAC 任务。以下图显示了我们希望定义的基本层次结构：

![创建 RBAC 授权层次结构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_07_01.jpg)

该图显示了自上而下的继承关系。因此，所有者拥有所有在所有者框中列出的权限，同时继承来自成员和读者角色的所有权限。同样，成员继承自读者的权限。现在我们需要做的是在应用程序中建立这种权限层次结构。如前所述，实现这一点的一种方法是编写代码来利用`authManager` API。

使用 API 的示例代码如下，它创建了一个新角色和一个新操作，然后添加了角色和权限之间的关系：

```php
$auth=Yii::app()->authManager;  
$role=$auth->createRole('owner');
$auth->createOperation('createProject','create a new project');    
$role->addChild('createProject');
```

通过这段代码，我们首先获得了`authManager`的实例。然后我们使用它的`createRole()`、`createOperation()`和`addChild()`API 方法来创建一个新的`owner`角色和一个名为`createProject`的新操作。然后我们将权限添加到所有者角色。这只是演示了我们需要的层次结构的一小部分的创建；我们在前面的图表中概述的所有其余关系都需要以类似的方式创建。

我们可以创建一个新的数据库迁移，并将我们的代码放在那里以填充我们的权限层次结构。然而，为了演示在 Yii 应用程序中使用控制台命令，我们将采取不同的方法。我们将编写一个简单的 shell 命令，在命令行上执行。这将扩展我们用于创建初始应用程序的`yiic`命令行工具的命令选项。

### 编写控制台应用程序命令

我们在第二章*入门*中介绍了`yiic`命令行工具，当我们创建了一个新的“Hello, World!”应用程序时，以及在第四章*项目 CRUD*中，当我们用它来最初创建我们的 TrackStar web 应用程序的结构时。在创建和运行数据库迁移时，我们继续使用它。

`yiic`工具是 Yii 中的一个控制台应用程序，用于以命令形式执行任务。我们已经使用`webapp`命令创建新的应用程序，并使用`migrate`命令创建新的迁移文件并执行数据库迁移。Yii 中的控制台应用程序可以通过编写自定义命令轻松扩展，这正是我们要做的。我们将通过编写一个新的命令行工具来扩展`yiic`命令工具集，以便我们可以构建 RBAC 授权。

为控制台应用程序编写新命令非常简单。命令只是一个从`CConsoleCommand`扩展的类。它的工作方式类似于控制器类，它将解析输入的命令行选项，并将请求分派到命令类中指定的操作，其默认为`actionIndex()`。类的名称应该与所需的命令名称完全相同，后面跟着“Command”。在我们的情况下，我们的命令将简单地是“Rbac”，所以我们将我们的类命名为`RbacCommand`。最后，为了使这个命令可用于`yiic`控制台应用程序，我们需要将我们的类保存到`/protected/commands/`目录中，这是控制台命令的默认位置。

因此，创建一个新文件`/protected/commands/RbacCommand.php`。这个文件的内容太长，无法包含在内，但可以从本章的可下载代码或[gist.github.com/jeffwinesett](http://gist.github.com/jeffwinesett)中轻松获取。这个代码片段可以在[`gist.github.com/3779677`](https://gist.github.com/3779677)中找到。

可下载代码中的注释应该有助于讲述这里发生的事情。我们重写了`getHelp()`的基类实现，以添加一个额外的描述行。我们将在一分钟内展示如何显示帮助。所有真正的操作都发生在我们添加的两个操作`actionIndex()`和`actionDelete()`中。前者创建我们的 RBAC 层次结构，后者删除它。它们都确保应用程序有一个定义的有效`authManager`应用程序组件。然后，这两个操作允许用户在继续之前有最后一次取消请求的机会。如果使用此命令的用户表示他们想要继续，请求将继续。我们的两个操作都将继续清除 RBAC 表中先前输入的所有数据，而`actionIndex()`方法将创建一个新的授权层次结构。这里创建的层次结构正是我们之前讨论的那个。

我们可以看到，即使基于我们相当简单的层次结构，仍然需要大量的代码。通常，需要开发一个更直观的**图形用户界面**（**GUI**）来包装这些授权管理器 API，以提供一个易于管理角色、任务和操作的界面。我们在这里采取的方法是建立快速 RBAC 权限结构的好解决方案，但不适合长期维护可能会发生重大变化的权限结构。

### 注意

在现实世界的应用程序中，您很可能需要一个不同的、更交互式的工具来帮助维护 RBAC 关系。Yii 扩展库（[`www.yiiframework.com/extensions/`](http://www.yiiframework.com/extensions/)）提供了一些打包的解决方案。

有了这个文件，如果我们现在询问`yiic`工具帮助，我们将看到我们的新命令作为可用选项之一：

![编写控制台应用程序命令](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_07_03.jpg)

我们的`rbac`显示在列表中。但是，在我们尝试执行之前，我们需要为控制台应用程序配置`authManager`。您可能还记得，运行控制台应用程序时，会加载不同的配置文件，即`/protected/config/console.php`。我们需要在这个文件中添加与之前添加到`main.php`配置文件相同的`authManager`组件。打开`console.php`并将以下内容添加到组件列表中：

```php
'authManager'=>array(
'class'=>'CDbAuthManager',
'connectionID'=>'db',
'itemTable' =>'tbl_auth_item',
'itemChildTable' =>'tbl_auth_item_child',
'assignmentTable' =>'tbl_auth_assignment',
),
```

有了这个，我们现在可以尝试我们的新命令：

![编写控制台应用程序命令](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_07_04.jpg)

这正是我们在命令类的`getHelp()`方法中添加的帮助文本。您当然可以更详细地添加更多细节。让我们实际运行命令。由于`actionIndex()`是默认值，我们不必指定操作：

![编写控制台应用程序命令](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_07_05.jpg)

我们的命令已经完成，并且我们已经向新的数据库表中添加了适当的数据，以生成我们的授权层次结构。

由于我们还添加了一个`actionDelete()`方法来删除我们的层次结构，您也可以尝试一下：

```php
**$ ./yiic rbac delete**

```

在尝试这些操作完成后，确保再次运行命令以添加层次结构，因为我们需要它继续存在。

## 分配用户到角色

到目前为止，我们所做的一切都建立了一个授权层次结构，但尚未为用户分配权限。我们通过将用户分配到我们创建的三个角色之一，*owner*、*member*或*reader*来实现这一点。例如，如果我们想要将唯一用户 ID 为`1`的用户与`member`角色关联，我们将执行以下操作：

```php
**$auth=Yii::app()->authManager;**
**$auth->assign('member',1);**

```

一旦建立了这些关系，检查用户的访问权限就变得很简单。我们只需询问应用程序用户组件当前用户是否具有权限。例如，如果我们想要检查当前用户是否被允许创建新问题，我们可以使用以下语法：

```php
if( Yii::app()->user->checkAccess('createIssue'))
{
     //perform needed logic
}
```

在这个例子中，我们将用户 ID `1`分配给`成员`角色，由于在我们的授权层次结构中，成员角色继承了`createIssue`权限，假设我们以用户`1`的身份登录到应用程序中，这个`if()`语句将评估为`true`。

我们将在向项目添加新成员时添加此授权分配逻辑作为业务逻辑的一部分。我们将添加一个新表单，允许我们将用户添加到项目中，并在此过程中选择角色。但首先，我们需要解决用户角色需要在每个项目基础上实施的另一个方面。

## 在每个项目基础上为用户添加 RBAC 角色

我们现在已经建立了一个基本的 RBAC 授权模型，但这些关系适用于整个应用程序。TrackStar 应用程序的需求稍微复杂一些。我们需要在项目的上下文中为用户分配角色，而不仅仅是在整个应用程序中全局地分配。我们需要允许用户在不同的项目中担任不同的角色。例如，用户可能是一个项目的“读者”角色，第二个项目的“成员”角色，以及第三个项目的“所有者”角色。用户可以与许多项目相关联，并且他们被分配的角色需要特定于项目。

Yii 中的 RBAC 框架没有内置的东西可以满足这个要求。RBAC 模型只旨在建立角色和权限之间的关系。它不知道（也不应该知道）我们的 TrackStar 项目的任何信息。为了实现我们授权层次结构的这个额外维度，我们需要改变我们的数据库结构，以包含用户、项目和角色之间的关联。如果您还记得第五章中的内容，*管理问题*，我们已经创建了一个名为`tbl_project_user_assignment`的表，用于保存用户和项目之间的关联。我们可以修改这个表，以包含用户在项目中分配的角色。我们将添加一个新的迁移来修改我们的表：

```php
**$ cd /Webroot/trackstar/protected/**
**$ ./yiic migrate create add_role_to_tbl_project_user_assignment**

```

现在打开新创建的迁移文件，并实现以下`up()`和`down()`方法：

```php
public function up()
{
$this->addColumn('tbl_project_user_assignment', 'role', 'varchar(64)');
//the tbl_project_user_assignment.role is a reference 
     //to tbl_auth_item.name
$this->addForeignKey('fk_project_user_role', 'tbl_project_user_assignment', 'role', 'tbl_auth_item', 'name', 'CASCADE', 'CASCADE');
}

public function down()
{
$this->dropForeignKey('fk_project_user_role', 'tbl_project_user_assignment');
$this->dropColumn('tbl_project_user_assignment', 'role');
}
```

最后运行迁移：

![在每个项目基础上为用户添加 RBAC 角色](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_07_06.jpg)

您将在屏幕底部看到消息“成功迁移”。

现在我们的表已经设置好，可以允许我们进行角色关联以及用户和项目之间的关联。

### 添加 RBAC 业务规则

虽然之前显示的数据库表将保存基本信息，以回答用户是否在特定项目的上下文中被分配了角色的问题，但我们仍然需要我们的 RBAC`auth`层次结构来回答关于用户是否有权限执行某个功能的问题。尽管 Yii 中的 RBAC 模型不知道我们的 TrackStar 项目，但它具有一个非常强大的功能，我们可以利用它。当您创建授权项或将项分配给用户时，您可以关联一小段 PHP 代码，该代码将在`Yii::app()->user->checkAccess()`调用期间执行。一旦定义，这段代码必须在用户被授予权限之前返回`true`。

这个功能的一个例子是在允许用户维护个人资料信息的应用程序中。在这种情况下，应用程序希望确保用户只有权限更新自己的个人资料信息，而不是其他人的。在这种情况下，我们可以创建一个名为“updateProfile”的授权项，然后关联一个业务规则，检查当前用户的 ID 是否与与个人资料信息相关联的用户 ID 相同。

在我们的情况下，我们将为角色分配关联一个业务规则。当我们将用户分配给特定角色时，我们还将关联一个业务规则，该规则将在项目的上下文中检查关系。`checkAccess()`方法还允许我们传递一个附加参数数组，供业务规则使用以执行其逻辑。我们将使用这个来传递当前项目上下文，以便业务规则可以调用`Project` AR 类的方法，以确定用户是否在该项目中被分配到该角色。

我们将为每个角色分配创建稍有不同的业务规则。例如，当将用户分配给所有者角色时，我们将使用以下规则：

```php
$bizRule='return isset($params["project"]) && $params["project"]->isUserInRole("owner");';
```

角色`成员`和`读者`的方法将会相似。

当我们调用`checkAccess()`方法时，我们还需要传递项目上下文。因此，现在在检查用户是否有权限执行例如`createIssue`操作时，代码将如下所示：

```php
//add the project AR instance to the input params
$params=array('project'=>$project);
//pass in the params to the checkAccess call
if(Yii::app()->user->checkAccess('createIssue',$params))
{
     //proceed with issue creation logic
}
```

在前面的代码中，`$project`变量是与当前项目上下文相关联的`Project` AR 类实例（请记住，我们应用程序中的几乎所有功能都发生在项目的上下文中）。这个类实例是业务规则中使用的。业务规则调用`Project::isUserInRole()`方法，以确定用户是否在特定项目的角色中。

### 实现新的项目 AR 方法

现在我们已经修改了数据库结构，以容纳用户、角色和项目之间的关系，我们需要实现所需的逻辑来管理和验证该表中的数据。我们将在项目 AR 类中添加公共方法，以处理从该表中添加和删除数据以及验证行的存在。

我们需要在`Project` AR 类中添加一个公共方法，该方法将接受角色名称和用户 ID，并创建角色、用户和项目之间的关联。打开`protected/models/Project.php`文件，并添加以下方法：

```php
public function assignUser($userId, $role)
{
$command = Yii::app()->db->createCommand();
$command->insert('tbl_project_user_assignment', array(
'role'=>$role,
'user_id'=>$userId,
'project_id'=>$this->id,
));
}
```

在这里，我们使用 Yii 框架的查询构建器方法直接插入数据库表，而不是使用活动记录方法。由于`tbl_project_user_assignement`只是一个关联表，并不代表我们模型的主要领域对象，因此有时更容易以更直接的方式管理这些类型表中的数据，而不是使用活动记录方法。

### 注意

有关在 Yii 中使用查询构建器的更多信息，请访问：

[`www.yiiframework.com/doc/guide/1.1/en/database.query-builder`](http://www.yiiframework.com/doc/guide/1.1/en/database.query-builder)

我们还需要能够从项目中删除用户，并在这样做时，删除用户和项目之间的关联。因此，让我们也添加一个执行此操作的方法。

在`Project` AR 类中添加以下方法：

```php
public function removeUser($userId)
{
$command = Yii::app()->db->createCommand();
$command->delete(
'tbl_project_user_assignment', 
'user_id=:userId AND project_id=:projectId', 
array(':userId'=>$userId,':projectId'=>$this->id));
}
```

这只是从包含角色、用户和项目之间关联的表中删除行。

我们现在已经实现了添加和删除关联的方法。我们需要添加功能来确定给定用户是否与项目内的角色相关联。我们还将这作为公共方法添加到我们的`Project` AR 类中。

在`Project` AR 模型类的底部添加以下方法：

```php
public function allowCurrentUser($role)
{
$sql = "SELECT * FROM tbl_project_user_assignment WHERE project_id=:projectId AND user_id=:userId AND role=:role";
$command = Yii::app()->db->createCommand($sql);
$command->bindValue(":projectId", $this->id, PDO::PARAM_INT);
$command->bindValue(":userId", Yii::app()->user->getId(), PDO::PARAM_INT);
$command->bindValue(":role", $role, PDO::PARAM_STR);
return $command->execute()==1;
}
```

该方法展示了如何直接执行 SQL，而不是使用查询构建器。查询构建器非常有用，但对于简单的查询，直接执行 SQL 有时更容易，利用 Yii 的数据访问对象（DAO）。

### 注意

有关 Yii 的数据访问对象和在 Yii 中直接执行 SQL 的更多信息，请参阅：

[`www.yiiframework.com/doc/guide/1.1/en/database.dao`](http://www.yiiframework.com/doc/guide/1.1/en/database.dao)

## 将用户添加到项目中

现在我们需要把所有这些放在一起。在第六章中，*用户管理和授权*中，我们添加了创建应用程序新用户的功能。然而，我们还没有办法将用户分配给特定的项目，并进一步将他们分配到这些项目中的角色。现在我们已经有了 RBAC 方法，我们需要构建这个新功能。

这个功能的实现涉及几个编码更改。然而，我们已经提供了类似的需要的更改的示例，并在之前的章节中涵盖了所有相关的概念。因此，我们将快速地进行这个过程，并且只是简要地强调一些我们还没有看到的东西。此时，读者应该能够在没有太多帮助的情况下进行所有这些更改，并被鼓励以实践的方式这样做。为了进一步鼓励这种练习，我们将首先列出我们要做的一切来满足这个新的功能需求。然后你可以关闭书本，在查看我们的实现之前尝试一些这样的操作。

为了实现这个目标，我们将执行以下操作：

1.  在`Project`模型类中添加一个名为`getUserRoleOptions()`的新公共静态方法，该方法使用`auth`管理器的`getRoles()`方法返回一个有效的角色选项列表。我们将使用这个方法来填充表单中的角色选择下拉字段，以便在向项目添加新用户时选择用户角色。

1.  在`Project`模型类中添加一个名为`isUserInProject($user)`的新公共方法，以确定用户是否已经与项目关联。我们将在表单提交时使用这个方法来进行验证规则，以便我们不会尝试将重复的用户添加到项目中。

1.  添加一个名为`ProjectUserForm`的新表单模型类，继承自`CFormModel`，用于新的输入表单模型。在这个表单模型类中添加三个属性，即`$username`、`$role`和`$project`。还要添加验证规则，以确保用户名和角色都是必需的输入字段，并且用户名应该通过自定义的`verify()`类方法进行进一步验证。

这个验证方法应该尝试通过查找与输入用户名匹配的用户来创建一个新的 UserAR 类实例。如果尝试成功，它应该继续使用我们之前添加的`assignUser($userId, $role)`方法将用户关联到项目。我们还需要在本章前面实现的 RBAC 层次结构中将用户与角色关联起来。如果没有找到与用户名匹配的用户，它需要设置并返回一个错误。（如果需要，可以查看`LoginForm::authenticate()`方法作为自定义验证规则方法的示例。）

1.  在 views/project 下添加一个名为`adduser.php`的新视图文件，用于显示我们向项目添加用户的新表单。这个表单只需要两个输入字段，*用户名*和*角色*。角色应该是一个下拉选择列表。

1.  在`ProjectController`类中添加一个名为`actionAdduser()`的新控制器动作方法，并修改其`accessRules()`方法以确保经过身份验证的成员可以访问它。这个新的动作方法负责呈现新的视图来显示表单，并在提交表单时处理后退。

再次鼓励读者首先尝试自己进行这些更改。我们在以下部分列出了我们的代码更改。

### 修改项目模型类

对于`Project`类，我们添加了两个新的公共方法，其中一个是静态的，因此可以在不需要特定类实例的情况下调用：

```php
   /**
 * Returns an array of available roles in which a user can be placed when being added to a project
 */
public static function getUserRoleOptions()
{
return CHtml::listData(Yii::app()->authManager->getRoles(), 'name', 'name');
} 

/* 
 * Determines whether or not a user is already part of a project
 */
public function isUserInProject($user) 
{
$sql = "SELECT user_id FROM tbl_project_user_assignment WHERE project_id=:projectId AND user_id=:userId";
$command = Yii::app()->db->createCommand($sql);
$command->bindValue(":projectId", $this->id, PDO::PARAM_INT);
$command->bindValue(":userId", $user->id, PDO::PARAM_INT);
return $command->execute()==1;
}
```

### 添加新的表单模型类

就像在登录表单的方法中使用的那样，我们将创建一个新的表单模型类，作为存放我们的表单输入参数和集中验证的中心位置。这是一个相当简单的类，它继承自 Yii 类`CFormModel`，并具有映射到我们表单输入字段的属性，以及一个用于保存有效项目上下文的属性。我们需要项目上下文来能够向项目添加用户。整个类太长了，无法在这里列出，但可以轻松从本章附带的可下载代码中获取。独立的代码片段可以在[`gist.github.com/3779690`](http:// https://gist.github.com/3779690)上找到。

在下面的代码片段中，我们列出了我们以前没有见过的部分：

```php
class ProjectUserForm extends CFormModel
{
…
      public function assign()
{
if($this->_user instanceof User)
{
//assign the user, in the specified role, to the project
$this->project->assignUser($this->_user->id, $this->role);  
//add the association, along with the RBAC biz rule, to our RBAC hierarchy
        $auth = Yii::app()->authManager; 
$bizRule='return isset($params["project"]) && $params["project"]->allowCurrentUser("'.$this->role.'");';  
$auth->assign($this->role,$this->_user->id, $bizRule);
                  return true;
}
            else
{
$this->addError('username','Error when attempting to assign this user to the project.'); 
return false;
}
      }
```

### 注意

为了简单起见，在`createUsernameList()`方法中，我们选择从数据库中选择*所有*用户来用于用户名列表。如果有大量用户，这可能会导致性能不佳。为了优化性能，在用户数量较多的情况下，您可能需要对其进行过滤和限制。

我们在可下载的代码部分中列出的部分是`assign()`方法，我们在其中为用户和角色之间的关联添加了一个 bizRule：

```php
$auth = Yii::app()->authManager; 
$bizRule='return isset($params["project"]) && $params["project"]->isUserInRole("'.$this->role.'");';
$auth->assign($this->role,$user->id, $bizRule);
```

我们创建了一个`Authmanager`类的实例，用于建立用户与角色的分配。然而，在进行分配之前，我们需要创建业务规则。业务规则使用`$params`数组，首先检查数组中是否存在`project`元素，然后在项目 AR 类上调用`isUserInRole()`方法，该方法是该数组元素的值。我们明确向这个方法传递角色名。然后我们调用`AuthManager::assign()`方法来建立用户与角色之间的关联。

我们还添加了一个简单的公共方法`createUsernameList()`，返回数据库中所有用户名的数组。我们将使用这个数组来填充 Yii 的 UI 小部件`CJuiAutoComplete`的数据，我们将用它来填充用户名输入表单元素。正如它的名字所示，当我们在输入表单字段中输入时，它将根据这个数组中的元素提供选择建议。

### 向项目控制器添加新的动作方法

我们需要一个控制器动作来处理显示向项目添加新用户的表单的初始请求。我们将其放在`ProjectController`类中，并命名为`actionAdduser()`。其代码如下：

```php
     /**
 * Provides a form so that project administrators can
 * associate other users to the project
 */
public function actionAdduser($id)
{
  $project = $this->loadModel($id);
  if(!Yii::app()->user->checkAccess('createUser', array('project'=>$project)))
{
  throw new CHttpException(403,'You are not authorized to perform this action.');
}

  $form=new ProjectUserForm; 
  // collect user input data
  if(isset($_POST['ProjectUserForm']))
  {
    $form->attributes=$_POST['ProjectUserForm'];
    $form->project = $project;
    // validate user input  
    if($form->validate())  
    {
        if($form->assign())
      {
       Yii::app()->user->setFlash('success',$form->username . " has been added to the project." ); 
       //reset the form for another user to be associated if desired
      $form->unsetAttributes();
      $form->clearErrors();
      }
    }
  }
$form->project = $project;
$this->render('adduser',array('model'=>$form)); 
}
```

这对我们来说都很熟悉。它处理了显示表单的初始`GET`请求，以及表单提交后的`POST`请求。它非常类似于我们的`SiteController::actionLogin()`方法。然而，在上一个代码片段中突出显示的代码是我们以前没有见过的。如果提交的表单请求成功，它会设置一个称为**flash message**的东西。Flash message 是一个临时消息，暂时存储在会话中。它只在当前和下一个请求中可用。在这里，我们使用我们的`CWebUser`应用用户组件的`setFlash()`方法来存储一个临时消息，表示请求成功。当我们在下一节讨论视图时，我们将看到如何访问此消息并将其显示给用户。

我们需要做的另一个更改是基本控制器类方法`Controller::accessRules()`。您还记得，我们将访问规则添加到这个基类中，以便它们适用于我们的每个用户、问题和项目控制器类。我们需要将这个新动作名称添加到基本访问规则列表中，以便允许已登录用户访问此动作：

```php
public function accessRules()
{
return array(
array('allow',  // allow all users to perform 'index' and 'view' actions
'controllers'=>array('issue','project','user'),
'actions'=>array('index','view',**'addUser'**),
'users'=>array('@'),
),
```

### 添加新的视图文件来显示表单

我们的新动作方法调用`->render('adduser')`来渲染一个视图文件，所以我们需要创建一个。以下是我们对`protected/views/project/adduser.php`的实现的完整列表：

```php
<?php
$this->pageTitle=Yii::app()->name . ' - Add User To Project';
$this->breadcrumbs=array(
$model->project->name=>array('view','id'=>$model->project->id),
'Add User',
);
$this->menu=array(
array('label'=>'Back To Project', 'url'=>array('view','id'=>$model->project->id)),
);
?>

<h1>Add User To <?php echo $model->project->name; ?></h1>

**<?php if(Yii::app()->user->hasFlash('success')):?>**
**<div class="successMessage">**
**<?php echo Yii::app()->user->getFlash('success'); ?>**
**</div>**
**<?phpendif; ?>**

<div class="form">
<?php $form=$this->beginWidget('CActiveForm'); ?>

<p class="note">Fields with <span class="required">*</span> are required.</p>

<div class="row">
<?php echo $form->labelEx($model,'username'); ?>
<?php
$this->widget('zii.widgets.jui.CJuiAutoComplete', array(
'name'=>'username',
'source'=>$model->createUsernameList(),
'model'=>$model,
'attribute'=>'username',
'options'=>array(
'minLength'=>'2',
),
'htmlOptions'=>array(
'style'=>'height:20px;'
),
));
?>
<?php echo $form->error($model,'username'); ?>
</div>

<div class="row">
<?php echo $form->labelEx($model,'role'); ?>
<?php
echo $form->dropDownList($model,'role', 
Project::getUserRoleOptions()); ?>
<?php echo $form->error($model,'role'); ?>
</div>

<div class="row buttons">
<?php echo CHtml::submitButton('Add User'); ?>
</div>

<?php $this->endWidget(); ?>
</div>
```

我们以前大部分都见过了。我们正在定义活动标签和活动表单元素，这些元素直接与我们的`ProjectUserForm`表单模型类相关联。我们使用我们在项目模型类上早期实施的静态方法填充下拉菜单。我们使用`createUsernameList()`方法填充我们的 Zii 库自动完成小部件（`CJuiAutoComplete`）数据，该方法已添加到项目用户表单模型类中。我们还在菜单选项中添加了一个简单的链接，以便返回到项目详细信息页面。

在上一个代码片段中突出显示的代码对我们来说是新的。这是一个示例，说明了我们在`actionAdduser()`方法中引入并使用的闪烁消息。我们通过询问同一用户组件是否有闪烁消息（使用`hasFlash('succcess')`）来访问我们使用`setFlash()`设置的消息。我们向`hasFlash()`方法提供了我们在设置消息时给它的确切名称。这是向用户提供有关其先前请求的一些简单反馈的好方法。

我们做的另一个小改变是在项目详细信息页面中添加了一个简单的链接，以便我们可以从应用程序中访问它。以下突出显示的行已添加到项目`view.php`视图文件的菜单数组中：

```php
$this->menu=array(
…
array('label'=>'Add User To Project', 'url'=>array('project/adduser', 'id'=>$model->id)),
);
```

这使我们在查看项目详细信息时可以访问新表单。

### 将所有内容放在一起

有了所有这些变化，我们可以通过查看项目详细信息页面之一来导航到我们的新表单。例如，当通过`http://localhost/trackstar/index.php?r=project/view&id=1`查看项目 ID＃1 时，在右侧列操作菜单中有一个超链接**[将用户添加到项目]**，单击该链接应显示以下页面：

![将所有内容放在一起](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_07_02.jpg)

您可以使用我们以前构建的表单来创建新项目和用户，以确保将其中一些添加到应用程序中。然后，您可以尝试将用户添加到项目中。当您在**用户名**字段中输入时，您将看到自动完成的建议。如果您尝试添加一个不在用户数据库表中的用户，您应该会看到一个告诉您的错误。如果您尝试输入已添加到项目中的用户，您将收到一个告诉您的错误。在成功添加后，您将看到一个指示成功的简短闪烁消息。

现在我们有了将用户分配给项目并将它们添加到我们的 RBAC 授权层次结构的能力，我们应该改变我们添加新项目时的逻辑。添加新项目时，应将添加项目的用户分配为项目的“所有者”。这样，项目的创建者将对项目拥有完全的管理访问权限。我将把这留给读者作业。您可以通过下载附带本书的 TrackStar 应用程序的可用源代码来查看此练习的解决方案。

# 检查授权级别

完成本章中我们设定的任务的最后一件事是为我们实现的不同功能添加授权检查。在本章的早些时候，我们概述并实施了我们拥有的不同角色的 RBAC 授权层次结构。一切都已准备就绪，以允许或拒绝基于已授予项目内用户的权限的功能访问，但有一个例外。当尝试请求功能时，我们尚未实施必要的授权检查。该应用程序仍在使用在我们的项目、问题和用户控制器上定义的简单访问过滤器。我们将为我们的权限之一执行此操作，然后将其余实现留给读者作为练习。

回顾我们的授权层次结构，我们可以看到只有项目所有者才能向项目添加新用户。因此，让我们添加这个授权检查。除非当前用户在该项目的*owner*角色中，否则我们将隐藏项目详情页面上添加用户的链接（在实施之前，您应该确保您已经向项目添加了至少一个所有者和一个成员或读者，以便在完成后进行测试）。打开`protected/views/project/view.php`视图文件，在那里我们放置了添加新用户的菜单项。从菜单数组项中删除该数组元素，然后只有当`checkAccess()`方法返回`true`时，才将其推送到数组的末尾。以下代码显示了菜单项应该如何定义：

```php
$this->menu=array(
array('label'=>'List Project', 'url'=>array('index')),
array('label'=>'Create Project', 'url'=>array('create')),
array('label'=>'Update Project', 'url'=>array('update', 'id'=>$model->id)),
array('label'=>'Delete Project', 'url'=>'#', 'linkOptions'=>array('submit'=>array('delete','id'=>$model->id),'confirm'=>'Are you sure you want to delete this item?')),
array('label'=>'Manage Project', 'url'=>array('admin')),
array('label'=>'Create Issue', 'url'=>array('issue/create', 'pid'=>$model->id)),

);
if(Yii::app()->user->checkAccess('createUser',array('project'=>$model)))
{
$this->menu[] = array('label'=>'Add User To Project', 'url'=>array('adduser', 'id'=>$model->id));
}
```

这实现了我们在本章中讨论过的相同方法。我们在当前用户上调用`checkAccess()`并发送我们想要检查的权限的名称。此外，由于我们的角色是在项目的上下文中的，我们将项目模型实例作为数组输入发送。这将允许已在授权分配中定义的业务规则执行。现在，如果我们以特定项目的项目所有者身份登录，并导航到该项目的详情页面，我们将看到添加新用户到项目的菜单选项。相反，如果我们以同一项目的`member`或`reader`角色的用户身份登录，并再次导航到详情页面，这个链接将不会显示。

当然，这并不会阻止一个精明的用户通过直接使用 URL 导航来获得这个功能。例如，即使作为项目＃1 的`reader`角色的用户登录到应用程序，如果我直接导航到`http://localhost/trackstar/index.php?r=project/adduser&id=1`，我仍然可以访问表单。

为了防止这种情况发生，我们需要直接将我们的访问检查添加到动作方法本身。因此，在项目控制器类中的`ProjectController::actionAdduser()`方法中，我们可以添加检查：

```php
public function actionAdduser($id)
{
$project = $this->loadModel($id);
if(!Yii::app()->user->checkAccess('createUser', array('project'=>$project)))
{
throw new CHttpException(403,'You are not authorized to perform this action.');
}

$form=new ProjectUserForm; 
```

现在，当我们尝试直接访问这个 URL 时，除非我们是项目的*owner*角色，否则我们将被拒绝访问。

我们不会逐个实现所有其他功能的访问检查。每个都将以类似的方式实现。我们把这留给读者作为一个练习。这个实现对于继续跟随本书中剩余的代码示例并不是必需的。

# 总结

在本章中，我们涵盖了很多内容。首先，我们介绍了 Yii 提供的基本访问控制过滤器，作为允许和拒绝对特定控制器动作方法访问的一种方法。我们使用这种方法来确保用户在获得任何主要功能的访问权限之前必须登录到该应用程序。然后，我们详细介绍了 Yii 的 RBAC 模型，它允许更复杂的访问控制方法。我们基于应用程序角色构建了整个用户授权层次结构。在这个过程中，我们介绍了在 Yii 中编写控制台应用程序，并介绍了这一出色功能的一些好处。然后，我们增加了新功能，允许向项目添加用户，并能够将他们分配到这些项目中的适当角色。最后，我们发现了如何在整个应用程序中实现所需的访问检查，以利用 RBAC 层次结构来适当地授予/拒绝功能功能的访问权限。

在下一章中，我们将为用户添加更多功能，其中之一是能够在我们的项目问题上留下评论。


# 第八章：添加用户评论

通过前两章中对用户管理的实施，我们的 Trackstar 应用程序真的开始成形了。我们的主要应用程序功能的大部分功能现在已经完成。现在我们可以开始专注于一些很好有的功能。我们将首先解决的是用户在项目问题上留下评论的能力。

用户参与关于项目问题的对话的能力是任何问题跟踪工具应提供的重要部分。实现这一目标的一种方法是允许用户直接在问题上留下评论。评论将形成关于问题的对话，并提供即时和历史背景，以帮助跟踪任何问题的整个生命周期。我们还将使用评论来演示 Yii 小部件的使用以及如何建立一个小部件模型来向用户提供内容（有关小部件的更多信息，请参见[`en.wikipedia.org/wiki/Portlet`](http://en.wikipedia.org/wiki/Portlet)）。

# 功能规划

本章的目标是在 Trackstar 应用程序中实现功能，允许用户在问题上留下评论并阅读评论。当用户查看任何项目问题的详细信息时，他们应该能够阅读以前添加的所有评论，并在问题上创建新的评论。我们还希望在项目列表页面上添加一个小片段内容或小部件，以显示所有问题上最近留下的评论列表。这将是一个很好的方式，提供一个窗口进入最近的用户活动，并允许轻松访问最新的有活跃对话的问题。

以下是我们需要完成的高级任务列表：

1.  设计并创建一个新的数据库表来支持评论。

1.  创建与我们的新评论表相关的 Yii AR 类。

1.  在问题详细页面直接添加一个表单，允许用户提交评论。

1.  在问题的详细页面上显示与问题相关的所有评论列表。

1.  利用 Yii 小部件在项目列表页面上显示最近评论的列表。

# 创建模型

我们首先需要创建一个新的表来存放我们的评论。正如您所期望的那样，我们将使用数据库迁移来对我们的数据库结构进行这个添加：

```php
$ cd /Webroot/trackstar/protected
$ ./yiic migrate create create_user_comments_table
```

`up()`和`down()`方法如下：

```php
  public function up()
  {
    //create the issue table
    $this->createTable('tbl_comment', array(
      'id' => 'pk',
          'content' => 'text NOT NULL',
          'issue_id' => 'int(11) NOT NULL',
      'create_time' => 'datetime DEFAULT NULL',
      'create_user_id' => 'int(11) DEFAULT NULL',
      'update_time' => 'datetime DEFAULT NULL',
      'update_user_id' => 'int(11) DEFAULT NULL',
     ), 'ENGINE=InnoDB');

    //the tbl_comment.issue_id is a reference to tbl_issue.id 
    $this->addForeignKey("fk_comment_issue", "tbl_comment", "issue_id", "tbl_issue", "id", "CASCADE", "RESTRICT");

    //the tbl_issue.create_user_id is a reference to tbl_user.id 
    $this->addForeignKey("fk_comment_owner", "tbl_comment", "create_user_id", "tbl_user", "id", "RESTRICT, "RESTRICT");

    //the tbl_issue.updated_user_id is a reference to tbl_user.id 
    $this->addForeignKey("fk_comment_update_user", "tbl_comment", "update_user_id", "tbl_user", "id", "RESTRICT", "RESTRICT");

  }

  public function down()
  {
    $this->dropForeignKey('fk_comment_issue', 'tbl_comment');
    $this->dropForeignKey('fk_comment_owner', 'tbl_comment');
    $this->dropForeignKey('fk_comment_update_user', 'tbl_comment');
    $this->dropTable('tbl_comment');
  }
```

为了实现这个数据库更改，我们需要运行迁移：

```php
$ ./yiic migrate
```

现在我们的数据库表已经就位，创建相关的 AR 类就很容易了。我们在前几章中已经看到了很多次。我们知道如何做。我们只需使用 Gii 代码创建工具的**Model Generator**命令，并根据我们新创建的`tbl_comment`表创建一个名为`Comment`的 AR 类。如果需要，可以参考第四章*项目 CRUD*和第五章*管理问题*，了解使用此工具创建模型类的所有细节。

使用 Gii 工具为评论创建模型类后，您会注意到为我们生成的代码已经定义了一些关系。这些关系是基于我们在`tbl_comments`表上定义的外键关系。以下是为我们创建的内容：

```php
/**
   * @return array relational rules.
   */
  public function relations()
  {
    // NOTE: you may need to adjust the relation name and the related
    // class name for the relations automatically generated below.
    return array(
      'updateUser' => array(self::BELONGS_TO, 'User', 'update_user_id'),
      'issue' => array(self::BELONGS_TO, 'Issue', 'issue_id'),
      'createUser' => array(self::BELONGS_TO, 'User', 'create_user_id'),
    );
  }
```

我们可以看到我们有一个关系，指定评论属于一个问题。但我们还需要定义一个问题和它的评论之间的一对多关系。一个问题可以有多个评论。这个更改需要在`Issue`模型类中进行。

### 注意

如果我们在创建 Issue 模型的同时创建了我们的评论模型，这个关系就会为我们创建。

除此之外，我们还将添加一个关系作为统计查询，以便轻松检索与给定问题相关的评论数量。以下是我们对`Issue::relations()`方法所做的更改：

```php
public function relations()
{
  return array(
    'requester' => array(self::BELONGS_TO, 'User', 'requester_id'),
    'owner' => array(self::BELONGS_TO, 'User', 'owner_id'),
    'project' => array(self::BELONGS_TO, 'Project', 'project_id'),
    'comments' => array(self::HAS_MANY, 'Comment', 'issue_id'),
    'commentCount' => array(self::STAT, 'Comment', 'issue_id'),
  );
}
```

这建立了问题和评论之间的一对多关系。它还定义了一个统计查询，允许我们轻松地检索任何给定问题实例的评论总数。

### 提示

统计查询

之前定义的`commentCount`关系是我们以前没有见过的一种新类型的关系。除了关联查询，Yii 还提供了所谓的统计或聚合关系。在对象之间存在一对多（`HAS_MANY`）或多对多（`MANY_MANY`）关系的情况下，这些关系非常有用。在这种情况下，我们可以定义统计关系，以便轻松地获取相关对象的总数。我们已经利用了这一点，在之前的关系声明中，以便轻松地检索任何给定问题实例的评论总数。有关在 Yii 中使用统计查询的更多信息，请参阅[`www.yiiframework.com/doc/guide/1.1/en/database.arr#statistical-query`](http://www.yiiframework.com/doc/guide/1.1/en/database.arr#statistical-query)。

我们还需要更改我们新创建的`Comment` AR 类，以扩展我们自定义的`TrackStarActiveRecord`基类，以便它从我们放置在`beforeSave()`方法中的逻辑中受益。只需修改类定义的开头，如下所示：

```php
<?php
      /**
 * This is the model class for table "tbl_comment".
 */
class Comment extends TrackStarActiveRecord
{
```

我们将对`Comment::relations()`方法中的定义进行最后一次小的更改。在创建类时，关系属性已经为我们命名。让我们将名为`createUser`的属性更改为`author`，因为这个相关的用户代表评论的作者。这只是一个语义上的改变，但它将有助于使我们的代码更易于阅读和理解。将定义从`'createUser' => array(self::BELONGS_TO, 'User', 'create_user_id'),`更改为`'author' => array(self::BELONGS_TO, 'User', 'create_user_id')`。

# 创建评论 CRUD

现在我们已经有了 AR 模型类，创建用于管理相关实体的 CRUD 脚手架很容易。只需使用 Gii 代码生成工具的 Crud 生成器命令，参数为 AR 类名`Comment`。我们在之前的章节中已经看到了这个很多次，所以我们不会在这里再详细介绍。如果需要，可以参考第四章，*项目 CRUD*和第五章，*管理问题*，了解使用 Gii 工具创建 CRUD 脚手架代码的所有细节。虽然我们不会立即为我们的评论实现完整的 CRUD 操作，但是有其他操作的脚手架是很好的。

在使用 Gii 的 Crud 生成器之后，只要我们登录，现在我们应该能够通过以下 URL 查看自动生成的评论提交表单：

`http://localhost/trackstar/index.php?r=comment/create`

# 修改脚手架以满足我们的要求

正如我们以前经常看到的那样，我们经常需要调整自动生成的脚手架代码，以满足应用程序的特定要求。首先，我们用于创建新评论的自动生成表单为`tbl_comment`数据库表中定义的每个列都有一个输入字段。实际上，我们并不希望所有这些字段都成为表单的一部分。事实上，我们希望大大简化这个表单，只有一个用于评论内容的输入字段。而且，我们不希望用户通过之前提到的 URL 访问表单，而是只能通过访问问题详情页面来添加评论。用户将在查看问题详情的页面上添加评论。我们希望朝着以下截图所示的方式构建：

![修改脚手架以满足我们的要求](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_08_01.jpg)

为了实现这一点，我们将修改我们的`Issue`控制器类，以处理评论表单的提交，并修改问题详细信息视图，以显示现有评论和新评论创建表单。此外，由于评论应该只在问题的上下文中创建，我们将在问题模型类中添加一个新方法来创建新评论。

## 添加评论

正如前面提到的，我们将让问题实例创建自己的评论。为此，我们希望在`Issue` AR 类中添加一个方法。以下是该方法：

```php
/**
  * Adds a comment to this issue
  */
public function addComment($comment)
{
  $comment->issue_id=$this->id;
  return $comment->save();
}
```

该方法确保在保存新评论之前正确设置评论问题 ID。也就是说，当`Issue`的实例创建新评论时，我们知道该评论属于该问题。

有了这个方法，我们现在可以把重点转向问题控制器类。由于我们希望评论创建表单从`IssueController::actionView()`方法显示并将其数据发送回来，我们需要修改该方法。我们还将添加一个新的受保护方法来处理表单提交请求。首先，修改`actionView()`方法如下：

```php
public function actionView($id)
{
    $issue=$this->loadModel($id);
    $comment=$this->createComment($issue);
    $this->render('view',array(
      'model'=>$issue,
         'comment'=>$comment,
    ));
}
```

然后，添加以下受保护方法来创建一个新评论并处理创建此问题的新评论的表单提交请求：

```php
/**
  * Creates a new comment on an issue
  */
protected function createComment($issue)
{
  $comment=new Comment;  
  if(isset($_POST['Comment']))
  {
    $comment->attributes=$_POST['Comment'];
    if($issue->addComment($comment))
    {
      Yii::app()->user->setFlash('commentSubmitted',"Your comment has been added." );
      $this->refresh();
    }
  }
  return $comment;
}
```

我们的新受保护方法`createComment()`负责处理用户在问题上留下新评论时提交的`POST`请求。如果成功创建评论，我们设置一个闪存消息显示给用户，并进行页面刷新，以便我们的新评论将显示。当然，我们仍然需要修改我们的视图文件，以便所有这些显示给用户。对`IssueController::actionView()`所做的更改负责调用这个新方法，并为显示提供新评论实例。

## 显示表单

现在，我们需要修改我们的视图。首先，我们将创建一个新的视图文件来呈现我们的评论显示和评论输入表单。我们打算在另一个视图文件中显示此视图文件。因此，我们不希望再次显示所有一般页面组件，例如页眉导航和页脚信息。打算在其他视图文件中显示或不带任何额外装饰的视图文件称为**partial**视图。然后，您可以使用控制器方法`renderPartial()`，而不是`render()`方法。使用`renderPartial()`将仅呈现该视图文件中包含的内容，并且不会用任何其他内容装饰显示。当我们讨论使用布局和装饰视图文件时，我们将在第十章*让它看起来不错*中详细讨论这一点。

Yii 在创建部分视图文件时使用下划线（`_`）作为命名约定的前缀。由于我们将其呈现为部分视图，我们将遵循命名约定，并以下划线开头命名文件。在`protected/views/issue/`目录下创建一个名为`_comments.php`的新文件，并将以下代码添加到该文件中：

```php
<?php foreach($comments as $comment): ?>
<div class="comment">
      <div class="author">
    <?php echo CHtml::encode($comment->author->username); ?>:
  </div>

  <div class="time">
    on <?php echo date('F j, Y \a\t h:i a',strtotime($comment->create_time)); ?>
  </div>

  <div class="content">
    <?php echo nl2br(CHtml::encode($comment->content)); ?>
  </div>
     <hr>
</div><!-- comment -->
<?php endforeach; ?>
```

该文件接受评论实例数组作为输入参数，并逐个显示它们。现在，我们需要修改问题详细信息的视图文件以使用这个新文件。我们通过打开`protected/views/issue/view.php`并在文件末尾添加以下内容来实现这一点：

```php
<div id="comments">
  <?php if($model->commentCount>=1): ?>
    <h3>
      <?php echo $model->commentCount>1 ? $model->commentCount . ' comments' : 'One comment'; ?>
    </h3>

    <?php $this->renderPartial('_comments',array(
      'comments'=>$model->comments,
    )); ?>
  <?php endif; ?>

  <h3>Leave a Comment</h3>

  <?php if(Yii::app()->user->hasFlash('commentSubmitted')): ?>
    <div class="flash-success">
      <?php echo Yii::app()->user->getFlash('commentSubmitted'); ?>
    </div>
  <?php else: ?>
    <?php $this->renderPartial('/comment/_form',array(
      'model'=>$comment,
    )); ?>
  <?php endif; ?>

</div>
```

在这里，我们利用了我们之前添加到`Issue` AR 模型类的统计查询属性`commentCount`。这使我们能够快速确定特定问题是否有任何可用的评论。如果有评论，它将继续使用我们的`_comments.php`显示视图文件来呈现它们。然后显示我们在使用 Gii Crud Generator 功能时为我们创建的输入表单。它还会显示成功保存评论时设置的简单闪存消息。

我们需要做的最后一个改变是评论输入表单本身。正如我们过去多次看到的那样，为我们创建的表单在底层`tbl_comment`表中定义了每一列的输入字段。这不是我们想要显示给用户的。我们希望将其变成一个简单的输入表单，用户只需要提交评论内容。因此，打开包含输入表单的视图文件，即`protected/views/comment/_form.php`，并编辑如下：

```php
<div class="form">
<?php $form=$this->beginWidget('CActiveForm', array(
  'id'=>'comment-form',
  'enableAjaxValidation'=>false,
)); ?>
       <p class="note">Fields with <span class="required">*</span> are required.</p>
       <?php echo $form->errorSummary($model); ?>
       <div class="row">
    <?php echo $form->labelEx($model,'content'); ?>
    <?php echo $form->textArea($model,'content',array('rows'=>6, 'cols'=>50)); ?>
    <?php echo $form->error($model,'content'); ?>
  </div>

  <div class="row buttons">
    <?php echo CHtml::submitButton($model->isNewRecord ? 'Create' : 'Save'); ?>
  </div>

<?php $this->endWidget(); ?>

</div>
```

有了这一切，我们可以访问问题列表页面查看评论表单。例如，如果我们访问`http://localhost/trackstar/index.php?r=issue/view&id=111`，我们将在页面底部看到以下评论输入表单：

![显示表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_08_02.jpg)

如果我们尝试提交评论而没有指定任何内容，我们将看到以下截图中所示的错误：

![显示表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_08_03.jpg)

然后，如果我们以`User One`的身份登录并提交评论`My first test comment`，我们将看到以下显示：

![显示表单](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_08_04.jpg)

# 创建一个最近评论的小部件

现在我们可以在问题上留下评论，我们将把重点转向本章的第二个目标。我们想要显示所有项目中留下的最近评论列表。这将提供应用程序中用户沟通活动的一个很好的快照。我们还希望以一种方式构建这个小的内容块，使它可以在站点的不同位置轻松重复使用。这在互联网上的许多网络门户应用程序中非常常见。这些小的内容片段通常被称为**portlet**，这也是为什么我们在本章开头提到构建 portlet 架构。您可以参考[`en.wikipedia.org/wiki/Portlet`](http://en.wikipedia.org/wiki/Portlet)了解更多关于这个主题的信息。

## 介绍 CWidget

幸运的是，Yii 已经准备好帮助我们实现这种架构。Yii 提供了一个名为`CWidget`的组件类，非常适合实现这种类型的架构。Yii 的**widget**是`CWidget`类的一个实例（或其子类），通常嵌入在视图文件中以显示自包含、可重用的用户界面功能。我们将使用 Yii 的 widget 来构建一个最近评论组件，并在主项目详情页面上显示它，以便我们可以看到与项目相关的所有问题的评论活动。为了演示重用的便利性，我们将进一步显示一个最近评论列表，跨所有项目在项目列表页面上。

### 命名作用域

要开始创建我们的小部件，我们首先要修改我们的`Comment` AR 模型类，以返回最近添加的评论。为此，我们将利用 Yii 的 AR 模型类中的另一个特性——命名作用域。

**命名作用域**允许我们指定一个命名查询，提供了一种优雅的方式来定义检索 AR 对象列表时的 SQL `where`条件。命名作用域通常在`CActiveRecord::scopes()`方法中定义为`name=>criteria`对。例如，如果我们想定义一个名为`recent`的命名作用域，它将返回最近的五条评论；我们可以创建`Comment::scopes()`方法如下：

```php
class Comment extends TrackStarActiveRecord
{
  ...
  public function scopes()
  {
    return array(
      'recent'=>array(
        'order'=>'create_time DESC',
        'limit'=>5,
      ),
    );
  }
...
}
```

现在，我们可以使用以下语法轻松检索最近评论的列表：

```php
$comments=Comment::model()->recent()->findAll();
```

您还可以链接命名作用域。如果我们定义了另一个命名作用域，例如`approved`（如果我们的应用程序在显示评论之前需要经过批准过程），我们可以获取最近批准的评论列表，如下所示：

```php
$comments=Comment::model()->recent()->approved()->findAll();
```

您可以看到通过将它们链接在一起，我们有一种灵活而强大的方式来在特定上下文中检索我们的对象。

命名范围必须出现在`find`调用的左侧（`find`，`findAll`，`findByPk`等），并且只能在类级上下文中使用。命名范围方法调用必须与`ClassName::model()`一起使用。有关命名范围的更多信息，请参见[`www.yiiframework.com/doc/guide/1.1/en/database.ar#named-scopes`](http://www.yiiframework.com/doc/guide/1.1/en/database.ar#named-scopes)。

命名范围也可以被参数化。在先前的评论`recent`命名范围中，我们在条件中硬编码了限制为`5`。然而，当我们调用该方法时，我们可能希望能够指定限制数量。这就是我们为评论设置命名范围的方式。要添加参数，我们以稍有不同的方式指定命名范围。我们不是使用`scopes()`方法来声明我们的范围，而是定义一个新的公共方法，其名称与范围名称相同。将以下方法添加到`Comment` AR 类中：

```php
public function recent($limit=5)
{
  $this->getDbCriteria()->mergeWith(
    array(         
    'order'=>'t.create_time DESC',         
      'limit'=>$limit,     
    )
  );     
  return $this;
}
```

关于这个查询条件的一件事是在 order 值中使用了`t`。这是为了帮助在与另一个具有相同列名的相关表一起使用时。显然，当两个被连接的表具有相同的列名时，我们必须在查询中区分这两个表。例如，如果我们在相同的查询中使用这个查询来检索`Issue` AR 信息，`tbl_issue`和`tbl_comment`表都有定义`create_time`列。我们试图按照`tbl_comment`表中的这一列进行排序，而不是在问题表中定义的那一列。在 Yii 的关系 AR 查询中，主表的别名固定为`t`，而关系表的别名默认情况下与相应的关系名称相同。因此，在这种情况下，我们指定`t.create_time`以指示我们要使用主表的列。

### Yii 中关于关系 AR 查询的更多信息

有了这种方法，我们可以将命名范围与急切加载方法结合起来，以检索相关的`Issue` AR 实例。例如，假设我们想要获取与 ID 为`1`的项目相关的最后十条评论，我们可以使用以下方法：

```php
$comments = Comment::model()->with(array('issue'=>array('condition'=>'project_id=1')))->recent(10)->findAll();
```

这个查询对我们来说是新的。在以前的查询中，我们没有使用许多这些选项。以前，我们使用不同的方法来执行关系查询：

+   加载 AR 实例

+   在`relations()`方法中定义的关系属性中访问

例如，如果我们想要查询与项目 ID＃1 关联的所有问题，我们将使用类似以下两行代码的内容：

```php
// First retrieve the project whose ID is 1
$project=Project::model()->findByPk(1);

// Then retrieve the project's issues (a relational query is actually being performed behind the scenes here)
$issues=$project->issues;
```

这种熟悉的方法使用了所谓的**懒加载**。当我们首次创建项目实例时，查询不会返回所有相关的问题。它只在以后明确请求它们时检索相关的问题，也就是当执行`$project->issues`时。这被称为“懒惰”，因为它等到以后请求时才加载问题。

这种方法非常方便，而且在那些不需要相关问题的情况下也可以非常高效。然而，在其他情况下，这种方法可能有些低效。例如，如果我们想要检索跨*N*项目的问题信息，那么使用这种懒惰的方法将涉及执行*N*个连接查询。根据*N*的大小，这可能非常低效。在这些情况下，我们有另一个选择。我们可以使用所谓的**急切加载**。

急切加载方法在请求主 AR 实例的同时检索相关的 AR 实例。这是通过在 AR 查询的`find()`或`findAll()`方法与`with()`方法一起使用来实现的。继续使用我们的项目示例，我们可以使用急切加载来检索所有项目的所有问题，只需执行以下一行代码：

```php
//retrieve all project AR instances along with their associated issue AR instances
$projects = Project::model()->with('issues')->findAll();
```

现在，在这种情况下，`$projects`数组中的每个项目 AR 实例已经具有其关联的`issues`属性，该属性填充有`Issue` AR 实例的数组。这是通过使用单个连接查询实现的。

因此，让我们回顾一下我们检索特定项目的最后十条评论的示例：

```php
$comments = Comment::model()->with(array('issue'=>array('condition'=>'project_id=1')))->recent(10)->findAll();
```

我们正在使用急切加载方法来检索问题以及评论，但这个方法稍微复杂一些。这个查询在`tbl_comment`和`tbl_issue`表之间指定了一个连接。这个关系 AR 查询基本上会执行类似于以下 SQL 语句的操作：

```php
SELECT tbl_comment.*, tbl_issue.* FROM tbl_comment LEFT OUTER JOIN tbl_issue ON (tbl_comment.issue_id=tbl_issue.id) WHERE (tbl_issue.project_id=1) ORDER BY tbl_comment.create_time DESC LIMIT 10;
```

掌握了 Yii 中延迟加载和急切加载的好处的知识后，我们应该调整`IssueController::actionView()`方法中加载问题模型的方式。由于我们已经修改了问题的详细视图以显示我们的评论，包括评论的作者，我们知道在调用`IssueController::loadModel()`时，使用急切加载方法加载评论以及它们各自的作者将更有效。为此，我们可以添加一个额外的参数作为简单的输入标志，以指示我们是否要加载评论。

修改`IssueController::loadModel()`方法如下：

```php
   public function loadModel($id, $withComments=false)
  {
    if($withComments)
      $model = Issue::model()->with(array('comments'=>array('with'=>'author')))->findByPk($id);
    else
      $model=Issue::model()->findByPk($id);
    if($model===null)
      throw new CHttpException(404,'The requested page does not exist.');
    return $model;
  }
```

在`IssueController`方法中有三个地方调用了`loadModel()`方法：`actionView`，`actionUpdate`和`actionDelete`。当我们查看问题详情时，我们只需要关联的评论。因此，我们已经将默认设置为不检索关联的评论。我们只需要修改`actionView()`方法，在`loadModel()`调用中添加`true`。

```php
public function actionView($id)
{
  $issue=$this->loadModel($id, true);
....
}
```

有了这个设置，我们将加载问题以及其所有关联的评论，并且对于每条评论，我们将加载关联的作者信息，只需一次数据库调用。

### 创建小部件

现在，我们已经准备好创建我们的新小部件，以利用之前提到的所有更改来显示我们的最新评论。

正如我们之前提到的，Yii 中的小部件是从框架类`CWidget`或其子类扩展的类。我们将把我们的新小部件添加到`protected/components/`目录中，因为该目录的内容已经在主配置文件中指定为在应用程序中自动加载。这样，我们就不必在每次使用时显式导入该类。我们将称我们的小部件为`RecentComments`，并在该目录中添加一个同名的`.php`文件。将以下类定义添加到这个新创建的`RecentComments.php`文件中：

```php
<?php
/**
     * RecentCommentsWidget is a Yii widget used to display a list of recent comments 
     */
class RecentCommentsWidget extends CWidget
{
    private $_comments;  
    public $displayLimit = 5;
    public $projectId = null;

    public function init()
        {
          if(null !== $this->projectId)
        $this->_comments = Comment::model()->with(array('issue'=>array('condition'=>'project_id='.$this->projectId)))->recent($this->displayLimit)->findAll();
      else
        $this->_comments = Comment::model()->recent($this->displayLimit)->findAll();
        }  

        public function getData()
        {
          return $this->_comments;
        }

        public function run()
        {
            // this method is called by CController::endWidget()    
            $this->render('recentCommentsWidget');
        }
}
```

创建新小部件时的主要工作是重写基类的`init()`和`run()`方法。`init()`方法初始化小部件，并在其属性被初始化后调用。`run()`方法执行小部件。在这种情况下，我们只需通过请求基于`$displayLimit`和`$projectId`属性的最新评论来初始化小部件，使用我们之前讨论过的查询。小部件本身的执行只是简单地呈现其关联的视图文件，我们还没有创建。按照惯例，小部件的视图文件放在与小部件相同的目录中的`views/`目录中，并且与小部件同名，但以小写字母开头。遵循这个惯例，创建一个新文件，其完全限定的路径是`protected/components/views/recentCommentsWidget.php`。创建后，在该文件中添加以下内容：

```php
<ul>
  <?php foreach($this->getData() as $comment): ?>  
    <div class="author">
      <?php echo $comment->author->username; ?> added a comment.
    </div>
    <div class="issue">      
       <?php echo CHtml::link(CHtml::encode($comment->issue->name), array('issue/view', 'id'=>$comment->issue->id)); ?>
      </div>

  <?php endforeach; ?>
</ul>
```

这调用了`RecentCommentsWidget::getData()`方法，该方法返回一个评论数组。然后遍历每个评论，显示添加评论的人以及留下评论的相关问题。

为了看到结果，我们需要将这个小部件嵌入到现有的控制器视图文件中。如前所述，我们希望在项目列表页面上使用这个小部件，以显示所有项目的最近评论，并且在特定项目详情页面上，只显示该特定项目的最近评论。

让我们从项目列表页面开始。负责显示该内容的视图文件是`protected/views/project/index.php`。打开该文件，并在底部添加以下内容：

```php
<?php $this->widget('RecentCommentsWidget'); ?>  
```

如果我们现在查看项目列表页面`http://localhost/trackstar/index.php?r=project`，我们会看到类似以下截图的内容：

![创建小部件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_08_05.jpg)

现在，我们通过调用小部件将我们的新最近评论数据嵌入到页面中。这很好，但我们可以进一步将我们的小部件显示为应用程序中所有其他潜在*小部件*的一致方式。我们可以利用 Yii 为我们提供的另一个类`CPortlet`来实现这一点。

### 介绍 CPortlet

`CPortlet`是 Zii 的一部分，它是 Yii 捆绑的官方扩展类库。它为所有小部件提供了一个不错的基类。它将允许我们渲染一个漂亮的标题以及一致的 HTML 标记，这样应用程序中的所有小部件都可以很容易地以类似的方式进行样式设置。一旦我们有一个渲染内容的小部件，比如我们的`RecentCommentsWidget`，我们可以简单地使用我们小部件的渲染内容作为`CPortlet`的内容，`CPortlet`本身也是一个小部件，因为它也是从`CWidget`继承而来。我们可以通过在`CPortlet`的`beginWidget()`和`endWiget()`调用之间放置我们对`RecentComments`小部件的调用来实现这一点，如下所示：

```php
<?php $this->beginWidget('zii.widgets.CPortlet', array(
  'title'=>'Recent Comments',
));  

$this->widget('RecentCommentsWidget');

$this->endWidget(); ?>
```

由于`CPortlet`提供了一个标题属性，我们将其设置为对我们的 portlet 有意义的内容。然后，我们使用`RecentComments`小部件的渲染内容来为 portlet 小部件提供内容。这样做的最终结果如下截图所示：

![介绍 CPortlet](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_08_06.jpg)

这与我们之前的情况并没有太大的变化，但现在我们已经将我们的内容放入了一个一致的容器中，这个容器已经在整个网站中使用。请注意右侧列菜单内容块和我们新创建的最近评论内容块之间的相似之处。我相信你不会感到意外，右侧列菜单块也是在`CPortlet`容器中显示的。查看`protected/views/layouts/column2.php`，这是一个在我们最初创建应用程序时由`yiic webapp`命令自动生成的文件，会发现以下代码：

```php
<?php
  $this->beginWidget('zii.widgets.CPortlet', array(
    'title'=>'Operations',
  ));
  $this->widget('zii.widgets.CMenu', array(
    'items'=>$this->menu,
    'htmlOptions'=>array('class'=>'operations'),
  ));
  $this->endWidget();
?>
```

因此，看来应用程序一直在利用小部件！

#### 将我们的小部件添加到另一个页面

让我们还将我们的小部件添加到项目详情页面，并将评论限制为与特定项目相关的评论。

在`protected/views/project/view.php`文件的末尾添加以下内容：

```php
<?php $this->beginWidget('zii.widgets.CPortlet', array(
  'title'=>'Recent Comments On This Project',
));  

$this->widget('RecentCommentsWidget', array('projectId'=>$model->id));

$this->endWidget(); ?>
```

这基本上与我们添加到项目列表页面的内容相同，只是我们通过向调用添加一个`name=>value`对的数组来初始化小部件的`$projectId`属性。

如果现在访问特定项目详情页面，我们应该会看到类似以下截图的内容：

![将我们的小部件添加到另一个页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/webapp-dev-yii-php/img/8727_08_07.jpg)

上述截图显示了**项目#1**的详情页面，该项目有一个关联的问题，该问题只有一个评论，如截图所示。您可能需要添加一些问题和这些问题的评论，以生成类似的显示。现在我们有一种方法可以在整个网站的任何地方以一致且易于维护的方式显示最近的评论。

# 总结

通过本章，我们已经开始为我们的 Trackstar 应用程序添加功能，这些功能已经成为当今大多数基于用户的 Web 应用程序所期望的。用户在应用程序内部相互通信的能力是成功的问题管理系统的重要组成部分。

当我们创建了这一重要功能时，我们能够更深入地了解如何编写关系 AR 查询。我们还介绍了称为小部件和门户网站的内容组件。这使我们能够开发小的内容块，并能够在应用程序的任何地方使用它们。这种方法极大地增加了重用性、一致性和易于维护性。

在下一章中，我们将在这里创建的最近评论小部件的基础上构建，并将我们小部件生成的内容作为 RSS 订阅公开，以便用户可以跟踪应用程序或项目的活动，而无需访问应用程序。
