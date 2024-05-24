# PHP7 编程秘籍（三）

> 原文：[`zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb`](https://zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：构建可扩展的网站

在本章中，我们将涵盖以下主题：

+   创建一个通用的表单元素生成器

+   创建一个 HTML 单选按钮元素生成器

+   创建一个 HTML 选择元素生成器

+   实现一个表单工厂

+   链接`$_POST`过滤器

+   链接`$_POST`验证器

+   将验证与表单绑定

# 介绍

在本章中，我们将向您展示如何构建生成 HTML 表单元素的类。通用元素生成器可用于文本、文本区域、密码和类似的 HTML 输入类型。之后，我们将展示允许您使用值数组预配置元素的变体。表单工厂配方将把所有这些生成器结合在一起，允许您使用单个配置数组渲染整个表单。最后，我们介绍允许过滤和验证传入`$_POST`数据的配方。

# 创建一个通用的表单元素生成器

创建一个简单的函数来输出一个表单输入标签，比如`<input type="text" name="whatever" >`。然而，为了使表单生成器通用有用，我们需要考虑更大的问题。除了基本的输入标签之外，我们还需要考虑一些其他方面：

+   表单`input`标签及其相关的 HTML 属性

+   告诉用户他们正在输入什么信息的标签

+   显示验证后的输入错误的能力（稍后详细介绍！）

+   某种包装器，比如`<div>`标签，或者 HTML 表格`<td>`标签

## 如何做...

1.  首先，我们定义一个`Application\Form\Generic`类。这也将作为专门的表单元素的基类：

```php
namespace Application\Form;

class Generic
{
  // some code ...
}
```

1.  接下来，我们定义一些类常量，这些常量在表单元素生成中通常很有用。

1.  前三个将成为与单个表单元素的主要组件相关联的键。然后我们定义支持的输入类型和默认值：

```php
const ROW = 'row';
const FORM = 'form';
const INPUT = 'input';
const LABEL = 'label';
const ERRORS = 'errors';
const TYPE_FORM = 'form';
const TYPE_TEXT = 'text';
const TYPE_EMAIL = 'email';
const TYPE_RADIO = 'radio';
const TYPE_SUBMIT = 'submit';
const TYPE_SELECT = 'select';
const TYPE_PASSWORD = 'password';
const TYPE_CHECKBOX = 'checkbox';
const DEFAULT_TYPE = self::TYPE_TEXT;
const DEFAULT_WRAPPER = 'div';
```

1.  接下来，我们可以定义属性和设置它们的构造函数。

1.  在这个例子中，我们需要两个属性`$name`和`$type`，因为没有这些属性我们无法有效地使用元素。其他构造函数参数是可选的。此外，为了基于另一个表单元素，我们包括一个规定，第二个参数`$type`可以替代地是`Application\Form\Generic`的实例，这样我们只需运行*getters*（稍后讨论）来填充属性：

```php
protected $name;
protected $type    = self::DEFAULT_TYPE;
protected $label   = '';
protected $errors  = array();
protected $wrappers;
protected $attributes;    // HTML form attributes
protected $pattern =  '<input type="%s" name="%s" %s>';

public function __construct($name, 
                $type, 
                $label = '',
                array $wrappers = array(), 
                array $attributes = array(),
                array $errors = array())
{
  $this->name = $name;
  if ($type instanceof Generic) {
      $this->type       = $type->getType();
      $this->label      = $type->getLabelValue();
      $this->errors     = $type->getErrorsArray();
      $this->wrappers   = $type->getWrappers();
      $this->attributes = $type->getAttributes();
  } else {
      $this->type       = $type ?? self::DEFAULT_TYPE;
      $this->label      = $label;
      $this->errors     = $errors;
      $this->attributes = $attributes;
      if ($wrappers) {
          $this->wrappers = $wrappers;
      } else {
          $this->wrappers[self::INPUT]['type'] =
            self::DEFAULT_WRAPPER;
          $this->wrappers[self::LABEL]['type'] = 
            self::DEFAULT_WRAPPER;
          $this->wrappers[self::ERRORS]['type'] = 
            self::DEFAULT_WRAPPER;
    }
  }
  $this->attributes['id'] = $name;
}
```

### 注意

请注意，`$wrappers`有三个主要的子键：`INPUT`、`LABEL`和`ERRORS`。这使我们能够为标签、输入标签和错误定义单独的包装器。

1.  在定义将生成标签、输入标签和错误的 HTML 的核心方法之前，我们应该定义一个`getWrapperPattern()`方法，它将为标签、输入和错误显示产生适当的*包装*标签。

1.  例如，如果包装器被定义为`<div>`，并且它的属性包括`['class' => 'label']`，这个方法将返回一个看起来像这样的`sprintf()`格式模式：`<div class="label">%s</div>`。例如，标签的最终 HTML 将替换`%s`。

1.  `getWrapperPattern()`方法可能如下所示：

```php
public function getWrapperPattern($type)
{
  $pattern = '<' . $this->wrappers[$type]['type'];
  foreach ($this->wrappers[$type] as $key => $value) {
    if ($key != 'type') {
      $pattern .= ' ' . $key . '="' . $value . '"';
    }
  }
  $pattern .= '>%s</' . $this->wrappers[$type]['type'] . '>';
  return $pattern;
}
```

1.  现在我们准备定义`getLabel()`方法。这个方法所需要做的就是使用`sprintf()`将标签插入包装器中：

```php
public function getLabel()
{
  return sprintf($this->getWrapperPattern(self::LABEL), 
                 $this->label);
}
```

1.  为了生成核心的`input`标签，我们需要一种方法来组装属性。幸运的是，只要它们以关联数组的形式提供给构造函数，这是很容易实现的。在这种情况下，我们只需要定义一个`getAttribs()`方法，它产生由空格分隔的键值对的字符串。我们使用`trim()`来去除多余的空格并返回最终值。

1.  如果元素包括`value`或`href`属性，出于安全原因，我们应该对值进行转义，假设它们是用户提供的（或可能是）（因此可疑）。因此，我们需要添加一个`if`语句来检查，然后使用`htmlspecialchars()`或`urlencode()`：

```php
public function getAttribs()
{
  foreach ($this->attributes as $key => $value) {
    $key = strtolower($key);
    if ($value) {
      if ($key == 'value') {
        if (is_array($value)) {
            foreach ($value as $k => $i) 
              $value[$k] = htmlspecialchars($i);
        } else {
            $value = htmlspecialchars($value);
        }
      } elseif ($key == 'href') {
          $value = urlencode($value);
      }
      $attribs .= $key . '="' . $value . '" ';
    } else {
        $attribs .= $key . ' ';
    }
  }
  return trim($attribs);
}
```

1.  对于核心输入标记，我们将逻辑分为两个独立的方法。主要方法`getInputOnly()`仅生成 HTML 输入标记。第二个方法`getInputWithWrapper()`生成包含在包装器中的输入。拆分的原因是在创建分支类时，例如生成单选按钮的类，我们将不需要包装器：

```php
public function getInputOnly()
{
  return sprintf($this->pattern, $this->type, $this->name, 
                 $this->getAttribs());
}

public function getInputWithWrapper()
{
  return sprintf($this->getWrapperPattern(self::INPUT), 
                 $this->getInputOnly());
}
```

1.  现在我们定义一个显示元素验证错误的方法。我们假设错误将以数组的形式提供。如果没有错误，我们返回一个空字符串。否则，错误将呈现为`<ul><li>error 1</li><li>error 2</li></ul>`等等：

```php
public function getErrors()
{
  if (!$this->errors || count($this->errors == 0)) return '';
  $html = '';
  $pattern = '<li>%s</li>';
  $html .= '<ul>';
  foreach ($this->errors as $error)
  $html .= sprintf($pattern, $error);
  $html .= '</ul>';
  return sprintf($this->getWrapperPattern(self::ERRORS), $html);
}
```

1.  对于某些属性，我们可能需要更精细的控制属性的各个方面。例如，我们可能需要将一个错误添加到已经存在的错误数组中。此外，设置单个属性可能很有用：

```php
public function setSingleAttribute($key, $value)
{
  $this->attributes[$key] = $value;
}
public function addSingleError($error)
{
  $this->errors[] = $error;
}
```

1.  最后，我们定义获取器和设置器，允许我们检索或设置属性的值。例如，您可能已经注意到`$pattern`的默认值是`<input type="%s" name="%s" %s>`。对于某些标签（例如`select`和`form`标签），我们需要将此属性设置为不同的值：

```php
public function setPattern($pattern)
{
  $this->pattern = $pattern;
}
public function setType($type)
{
  $this->type = $type;
}
public function getType()
{
  return $this->type;
}
public function addSingleError($error)
{
  $this->errors[] = $error;
}
// define similar get and set methods
// for name, label, wrappers, errors and attributes
```

1.  我们还需要添加一些方法，用于提供标签值（而不是 HTML）以及错误数组：

```php
public function getLabelValue()
{
  return $this->label;
}
public function getErrorsArray()
{
  return $this->errors;
}
```

## 工作原理...

确保将所有前面的代码复制到一个单独的`Application\Form\Generic`类中。然后，您可以定义一个`chap_06_form_element_generator.php`调用脚本，设置自动加载并锚定新类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Form\Generic;
```

接下来，定义包装器。作为示例，我们将使用 HTML 表数据和标题标签。请注意，标签使用`TH`，而输入和错误使用`TD`：

```php
$wrappers = [
  Generic::INPUT => ['type' => 'td', 'class' => 'content'],
  Generic::LABEL => ['type' => 'th', 'class' => 'label'],
  Generic::ERRORS => ['type' => 'td', 'class' => 'error']
];
```

现在，您可以通过向构造函数传递参数来定义电子邮件元素：

```php
$email = new Generic('email', Generic::TYPE_EMAIL, 'Email', $wrappers,
                    ['id' => 'email',
                     'maxLength' => 128,
                     'title' => 'Enter address',
                     'required' => '']);
```

或者，使用 setter 定义密码元素：

```php
$password = new Generic('password', $email);
$password->setType(Generic::TYPE_PASSWORD);
$password->setLabel('Password');
$password->setAttributes(['id' => 'password',
                          'title' => 'Enter your password',
                          'required' => '']);
```

最后，请确保定义一个提交按钮：

```php
$submit = new Generic('submit', 
  Generic::TYPE_SUBMIT,
  'Login',
  $wrappers,
  ['id' => 'submit','title' => 'Click to login','value' => 'Click Here']);
```

实际的显示逻辑可能如下所示：

```php
<div class="container">
  <!-- Login Form -->
  <h1>Login</h1>
  <form name="login" method="post">
  <table id="login" class="display" 
    cellspacing="0" width="100%">
    <tr><?= $email->render(); ?></tr>
    <tr><?= $password->render(); ?></tr>
    <tr><?= $submit->render(); ?></tr>
    <tr>
      <td colspan=2>
        <br>
        <?php var_dump($_POST); ?>
      </td>
    </tr>
  </table>
  </form>
</div>
```

这是实际的输出：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_06_01.jpg)

# 创建 HTML 单选按钮元素生成器

单选按钮元素生成器将与通用 HTML 表单元素生成器共享相似之处。与任何通用元素一样，一组单选按钮需要能够显示整体标签和错误。然而，有两个主要区别：

+   通常，您会希望有两个或更多的单选按钮

+   每个按钮都需要有自己的标签

## 如何做...

1.  首先，创建一个新的`Application\Form\Element\Radio`类，它扩展了`Application\Form\Generic`：

```php
**namespace Application\Form\Element;**
**use Application\Form\Generic;**
**class Radio extends Generic**
**{**
 **// code**
**}**

```

1.  接下来，定义与一组单选按钮的特殊需求相关的类常量和属性。

1.  在这个示例中，我们需要一个`spacer`，它将放置在单选按钮和其标签之间。我们还需要决定是在实际按钮之前还是之后放置单选按钮标签，因此我们使用`$after`标志。如果我们需要一个默认值，或者如果我们重新显示现有的表单数据，我们需要一种指定选定键的方法。最后，我们需要一个选项数组，我们将从中填充按钮列表：

```php
const DEFAULT_AFTER = TRUE;
const DEFAULT_SPACER = '&nbps;';
const DEFAULT_OPTION_KEY = 0;
const DEFAULT_OPTION_VALUE = 'Choose';

protected $after = self::DEFAULT_AFTER;
protected $spacer = self::DEFAULT_SPACER;
protected $options = array();
protected $selectedKey = DEFAULT_OPTION_KEY;
```

1.  鉴于我们正在扩展`Application\Form\Generic`，我们可以扩展`__construct()`方法，或者简单地定义一个可用于设置特定选项的方法。对于本示例，我们选择了后者。

1.  为了确保属性`$this->options`被填充，第一个参数（$options）被定义为强制性的（没有默认值）。所有其他参数都是可选的。

```php
public function setOptions(array $options, 
  $selectedKey = self::DEFAULT_OPTION_KEY, 
  $spacer = self::DEFAULT_SPACER,
  $after  = TRUE)
{
  $this->after = $after;
  $this->spacer = $spacer;
  $this->options = $options;
  $this->selectedKey = $selectedKey;
}  
```

1.  最后，我们准备覆盖核心的`getInputOnly()`方法。

1.  我们将`id`属性保存到一个独立的变量`$baseId`中，然后将其与`$count`组合，以便每个`id`属性都是唯一的。如果与选定键关联的选项已定义，则将其分配为值；否则，我们使用默认值：

```php
public function getInputOnly()
{
  $count  = 1;
  $baseId = $this->attributes['id'];
```

1.  在`foreach()`循环中，我们检查键是否是所选的键。如果是，就为该单选按钮添加`checked`属性。然后，我们调用父类的`getInputOnly()`方法来返回每个按钮的 HTML。请注意，输入元素的`value`属性是选项数组键。按钮标签是选项数组元素值：

```php
foreach ($this->options as $key => $value) {
  $this->attributes['id'] = $baseId . $count++;
  $this->attributes['value'] = $key;
  if ($key == $this->selectedKey) {
      $this->attributes['checked'] = '';
  } elseif (isset($this->attributes['checked'])) {
            unset($this->attributes['checked']);
  }
  if ($this->after) {
      $html = parent::getInputOnly() . $value;
  } else {
      $html = $value . parent::getInputOnly();
  }
  $output .= $this->spacer . $html;
  }
  return $output;
}
```

## 它是如何工作的...

将前面的代码复制到`Application/Form/Element`文件夹中的新`Radio.php`文件中。然后，您可以定义一个`chap_06_form_element_radio.php`调用脚本，设置自动加载并锚定新类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Form\Generic;
use Application\Form\Element\Radio;
```

接下来，使用前一个配方中定义的`$wrappers`数组来定义包装器。

然后，您可以定义一个`$status`数组，并通过向构造函数传递参数来创建一个元素实例：

```php
$statusList = [
  'U' => 'Unconfirmed',
  'P' => 'Pending',
  'T' => 'Temporary Approval',
  'A' => 'Approved'
];

$status = new Radio('status', 
          Generic::TYPE_RADIO, 
          'Status',
          $wrappers,
          ['id' => 'status']);
```

现在您可以查看是否有来自`$_GET`的状态输入，并设置选项。任何输入都将成为选定的键。否则，选定的键是默认值：

```php
$checked = $_GET['status'] ?? 'U';
$status->setOptions($statusList, $checked, '<br>', TRUE);          
```

最后，不要忘记定义一个提交按钮：

```php
$submit = new Generic('submit', 
          Generic::TYPE_SUBMIT,
          'Process',
          $wrappers,
          ['id' => 'submit','title' => 
          'Click to process','value' => 'Click Here']);
```

显示逻辑可能如下所示：

```php
<form name="status" method="get">
<table id="status" class="display" cellspacing="0" width="100%">
  <tr><?= $status->render(); ?></tr>
  <tr><?= $submit->render(); ?></tr>
  <tr>
    <td colspan=2>
      <br>
      <pre><?php var_dump($_GET); ?></pre>
    </td>
  </tr>
</table>
</form>
```

以下是实际输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_06_02.jpg)

## 还有更多...

复选框元素生成器几乎与 HTML 单选按钮生成器相同。主要区别在于一组复选框可以有多个选中的值。因此，您将使用 PHP 数组表示法来表示元素名称。元素类型应为`Generic::TYPE_CHECKBOX`。

# 创建 HTML 选择元素生成器

生成 HTML 单选元素类似于生成单选按钮的过程。然而，标签的结构不同，因为需要生成`SELECT`标签和一系列`OPTION`标签。

## 如何做到这一点...

1.  首先，创建一个新的`Application\Form\Element\Select`类，它扩展了`Application\Form\Generic`。

1.  我们之所以扩展`Generic`而不是`Radio`是因为元素的结构完全不同：

```php
namespace Application\Form\Element;

use Application\Form\Generic;

class Select extends Generic
{
  // code
}
```

1.  类常量和属性只需要稍微添加到`Application\Form\Generic`。与单选按钮或复选框不同，不需要考虑*间隔符*或所选文本的放置：

```php
const DEFAULT_OPTION_KEY = 0;
const DEFAULT_OPTION_VALUE = 'Choose';

protected $options;
protected $selectedKey = DEFAULT_OPTION_KEY;
```

1.  现在我们将注意力转向设置选项。由于 HTML 选择元素可以选择单个或多个值，因此`$selectedKey`属性可以是字符串或数组。因此，我们不为此属性添加**类型提示**。然而，重要的是要确定是否已设置`multiple`属性。这可以通过从父类继承的`$this->attributes`属性获得。

1.  如果已设置`multiple`属性，则将`name`属性构造为数组非常重要。因此，如果是这种情况，我们将在名称后附加`[]`：

```php
public function setOptions(array $options, $selectedKey = self::DEFAULT_OPTION_KEY)
{
  $this->options = $options;
  $this->selectedKey = $selectedKey;
  if (isset($this->attributes['multiple'])) {
    $this->name .= '[]';
  } 
}
```

### 注意

在 PHP 中，如果已设置 HTML 选择`multiple`属性，并且`name`属性未指定为数组，则只会返回单个值！

1.  在我们可以定义核心的`getInputOnly()`方法之前，我们需要定义一个方法来生成`select`标签。然后，我们使用`sprintf()`返回最终的 HTML，使用`$pattern`，`$name`和`getAttribs()`的返回值作为参数。

1.  我们用`<select name="%s" %s>`替换了`$pattern`的默认值。然后，我们循环遍历属性，将它们作为键值对添加到空格之间：

```php
protected function getSelect()
{
  $this->pattern = '<select name="%s" %s> ' . PHP_EOL;
  return sprintf($this->pattern, $this->name, 
  $this->getAttribs());
}
```

1.  接下来，我们定义一个方法来获取与`select`标签关联的`option`标签。

1.  正如您所记得的，`$this->options`数组中的*键*表示返回值，而数组的*值*部分表示将显示在屏幕上的文本。如果`$this->selectedKey`是数组形式，我们检查值是否在数组中。否则，我们假设`$this-> selectedKey`是一个字符串，我们只需确定它是否等于键。如果选定的键匹配，我们添加`selected`属性：

```php
protected function getOptions()
{
  $output = '';
  foreach ($this->options as $key => $value) {
    if (is_array($this->selectedKey)) {
        $selected = (in_array($key, $this->selectedKey)) 
        ? ' selected' : '';
    } else {
        $selected = ($key == $this->selectedKey) 
        ? ' selected' : '';
    }
        $output .= '<option value="' . $key . '"' 
        . $selected  . '>' 
        . $value 
        . '</option>';
  }
  return $output;
}
```

1.  最后，我们准备覆盖核心的`getInputOnly()`方法。

1.  您会注意到，此方法的逻辑只需要捕获前面代码中描述的`getSelect()`和`getOptions()`方法的返回值。我们还需要添加闭合的`</select>`标签：

```php
public function getInputOnly()
{
  $output = $this->getSelect();
  $output .= $this->getOptions();
  $output .= '</' . $this->getType() . '>'; 
  return $output;
}
```

## 它是如何工作的...

将上述代码复制到`Application/Form/Element`文件夹中的新`Select.php`文件中。然后定义一个`chap_06_form_element_select.php`调用脚本，设置自动加载并锚定新类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Form\Generic;
use Application\Form\Element\Select;
```

接下来，使用第一个配方中定义的数组`$wrappers`来定义包装器。您还可以使用*创建 HTML 单选按钮元素生成器*配方中定义的`$statusList`数组。然后，您可以创建`SELECT`元素的实例。第一个实例是单选，第二个是多选：

```php
$status1 = new Select('status1', 
           Generic::TYPE_SELECT, 
           'Status 1',
           $wrappers,
           ['id' => 'status1']);
$status2 = new Select('status2', 
           Generic::TYPE_SELECT, 
           'Status 2',
           $wrappers,
           ['id' => 'status2', 
            'multiple' => '', 
            'size' => '4']);
```

查看`$_GET`中是否有状态输入，并设置选项。任何输入都将成为选定的键。否则，选定的键是默认的。正如您所记得的，第二个实例是多选，因此从`$_GET`获取的值和默认设置都应该是数组形式：

```php
$checked1 = $_GET['status1'] ?? 'U';
$checked2 = $_GET['status2'] ?? ['U'];
$status1->setOptions($statusList, $checked1);
$status2->setOptions($statusList, $checked2);
```

最后，确保定义一个提交按钮（如本章*创建通用表单元素生成器*配方中所示）。

实际的显示逻辑与单选按钮配方相同，只是我们需要呈现两个单独的 HTML 选择实例：

```php
<form name="status" method="get">
<table id="status" class="display" cellspacing="0" width="100%">
  <tr><?= $status1->render(); ?></tr>
  <tr><?= $status2->render(); ?></tr>
  <tr><?= $submit->render(); ?></tr>
  <tr>
    <td colspan=2>
      <br>
      <pre>
        <?php var_dump($_GET); ?>
      </pre>
    </td>
  </tr>
</table>
</form>
```

这是实际输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_06_04.jpg)

此外，您可以看到元素如何出现在*查看源代码*页面中：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_06_05.jpg)

# 实施表单工厂

表单工厂的目的是从单个配置数组生成可用的表单对象。表单对象应具有检索其包含的各个元素的能力，以便可以生成输出。

## 如何做...

1.  首先，让我们创建一个名为`Application\Form\Factory`的类来包含工厂代码。它只有一个属性`$elements`，带有一个 getter：

```php
namespace Application\Form;

class Factory
{
  protected $elements;
  public function getElements()
  {
    return $this->elements;
  }
  // remaining code
}
```

1.  在定义主要的表单生成方法之前，重要的是考虑我们计划接收的配置格式，以及表单生成将产生什么。在本示例中，我们假设生成将产生一个具有`$elements`属性的`Factory`实例。该属性将是`Application\Form\Generic`或`Application\Form\Element`类的数组。

1.  我们现在准备着手编写`generate()`方法。这将循环遍历配置数组，创建适当的`Application\Form\Generic`或`Application\Form\Element\*`对象，然后将其存储在`$elements`数组中。新方法将接受配置数组作为参数。将此方法定义为静态的是方便的，这样我们可以使用不同的配置块生成所需的实例。

1.  我们创建一个`Application\Form\Factory`的实例，然后开始循环遍历配置数组：

```php
public static function generate(array $config)
{
  $form = new self();
  foreach ($config as $key => $p) {
```

1.  接下来，我们检查`Application\Form\Generic`类构造函数中的可选参数：

```php
  $p['errors'] = $p['errors'] ?? array();
  $p['wrappers'] = $p['wrappers'] ?? array();
  $p['attributes'] = $p['attributes'] ?? array();
```

1.  现在，所有构造函数参数都就位了，我们可以创建表单元素实例，然后将其存储在`$elements`中：

```php
  $form->elements[$key] = new $p['class']
  (
    $key, 
    $p['type'],
    $p['label'],
    $p['wrappers'],
    $p['attributes'],
    $p['errors']
  );
```

1.  接下来，我们将注意力转向选项。如果设置了`options`参数，我们使用`list()`将数组值提取到变量中。然后，我们使用`switch()`测试元素类型，并使用适当数量的参数运行`setOptions()`：

```php
    if (isset($p['options'])) {
      list($a,$b,$c,$d) = $p['options'];
      switch ($p['type']) {
        case Generic::TYPE_RADIO    :
        case Generic::TYPE_CHECKBOX :
          $form->elements[$key]->setOptions($a,$b,$c,$d);
          break;
        case Generic::TYPE_SELECT   :
          $form->elements[$key]->setOptions($a,$b);
          break;
        default                     :
          $form->elements[$key]->setOptions($a,$b);
          break;
      }
    }
  }
```

1.  最后，我们返回表单对象并关闭方法：

```php
  return $form;
} 
```

1.  理论上，在这一点上，我们可以通过简单地迭代元素数组并运行`render()`方法来在视图逻辑中轻松呈现表单。视图逻辑可能如下所示：

```php
<form name="status" method="get">
  <table id="status" class="display" cellspacing="0" width="100%">
    <?php foreach ($form->getElements() as $element) : ?>
      <?php echo $element->render(); ?>
    <?php endforeach; ?>
  </table>
</form>
```

1.  最后，我们返回表单对象并关闭方法。

1.  接下来，我们需要在`Application\Form\Element`下定义一个独立的`Form`类：

```php
namespace Application\Form\Element;
class Form extends Generic
{
  public function getInputOnly()
  {
    $this->pattern = '<form name="%s" %s> ' . PHP_EOL;
    return sprintf($this->pattern, $this->name, 
                   $this->getAttribs());
  }
  public function closeTag()
  {
    return '</' . $this->type . '>';
  }
}
```

1.  返回到`Application\Form\Factory`类，现在我们需要定义一个简单的方法，返回一个`sprintf()`包装器模式，作为输入的信封。例如，如果包装器是带有属性`class="test"`的`div`，我们将产生这个模式：`<div class="test">%s</div>`。然后我们的内容将被`sprintf()`函数替换为`%s`：

```php
protected function getWrapperPattern($wrapper)
{
  $type = $wrapper['type'];
  unset($wrapper['type']);
  $pattern = '<' . $type;
  foreach ($wrapper as $key => $value) {
    $pattern .= ' ' . $key . '="' . $value . '"';
  }
  $pattern .= '>%s</' . $type . '>';
  return $pattern;
}
```

1.  最后，我们准备定义一个执行整体表单渲染的方法。我们为每个表单行获取包装器`sprintf()`模式。然后我们循环遍历元素，渲染每个元素，并将输出包装在行模式中。接下来，我们生成一个`Application\Form\Element\Form`实例。然后我们检索表单包装器`sprintf()`模式，并检查`form_tag_inside_wrapper`标志，该标志告诉我们是否需要将表单标签放在表单包装器内部还是外部：

```php
public static function render($form, $formConfig)
{
  $rowPattern = $form->getWrapperPattern(
  $formConfig['row_wrapper']);
  $contents   = '';
  foreach ($form->getElements() as $element) {
    $contents .= sprintf($rowPattern, $element->render());
  }
  $formTag = new Form($formConfig['name'], 
                  Generic::TYPE_FORM, 
                  '', 
                  array(), 
                  $formConfig['attributes']); 

  $formPattern = $form->getWrapperPattern(
  $formConfig['form_wrapper']);
  if (isset($formConfig['form_tag_inside_wrapper']) 
      && !$formConfig['form_tag_inside_wrapper']) {
        $formPattern = '%s' . $formPattern . '%s';
        return sprintf($formPattern, $formTag->getInputOnly(), 
        $contents, $formTag->closeTag());
  } else {
        return sprintf($formPattern, $formTag->getInputOnly() 
        . $contents . $formTag->closeTag());
  }
}
```

## 它是如何工作...

参考前面的代码，创建`Application\Form\Factory`和`Application\Form\Element\Form`类。

接下来，您可以定义一个`chap_06_form_factor.php`调用脚本，设置自动加载并锚定新类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Form\Generic;
use Application\Form\Factory;
```

接下来，使用第一个配方中定义的`$wrappers`数组来定义包装器。您还可以使用第二个配方中定义的`$statusList`数组。

查看是否有来自`$_POST`的状态输入。任何输入都将成为所选键。否则，所选键是默认值。

```php
$email    = $_POST['email']   ?? '';
$checked0 = $_POST['status0'] ?? 'U';
$checked1 = $_POST['status1'] ?? 'U';
$checked2 = $_POST['status2'] ?? ['U'];
$checked3 = $_POST['status3'] ?? ['U'];
```

现在您可以定义整体表单配置。`name`和`attributes`参数用于配置`form`标签本身。另外两个参数代表表单级别和行级别的包装器。最后，我们提供一个`form_tag_inside_wrapper`标志，以指示表单标签不应出现在包装器内部（即`<table>`）。如果包装器是`<div>`，我们将将此标志设置为`TRUE`：

```php
$formConfig = [ 
  'name'         => 'status_form',
  'attributes'   => ['id'=>'statusForm','method'=>'post', 'action'=>'chap_06_form_factory.php'],
  'row_wrapper'  => ['type' => 'tr', 'class' => 'row'],
  'form_wrapper' => ['type'=>'table','class'=>'table', 'id'=>'statusTable',
                     'class'=>'display','cellspacing'=>'0'],
                     'form_tag_inside_wrapper' => FALSE,
];
```

接下来，定义一个数组，其中包含由工厂创建的每个表单元素的参数。数组键成为表单元素的名称，并且必须是唯一的：

```php
$config = [
  'email' => [  
    'class'     => 'Application\Form\Generic',
    'type'      => Generic::TYPE_EMAIL, 
    'label'     => 'Email', 
    'wrappers'  => $wrappers,
    'attributes'=> ['id'=>'email','maxLength'=>128, 'title'=>'Enter address',
                    'required'=>'','value'=>strip_tags($email)]
  ],
  'password' => [
    'class'      => 'Application\Form\Generic',
    'type'       => Generic::TYPE_PASSWORD,
    'label'      => 'Password',
    'wrappers'   => $wrappers,
    'attributes' => ['id'=>'password',
    'title'      => 'Enter your password',
    'required'   => '']
  ],
  // etc.
];
```

最后，确保生成表单：

```php
$form = Factory::generate($config);
```

实际的显示逻辑非常简单，因为我们只需调用表单级别的`render()`方法：

```php
<?= $form->render($form, $formConfig); ?>
```

这是实际输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_06_06.jpg)

# 使用$_POST 过滤器链接

当处理用户从在线表单提交的数据时，适当的过滤和验证是一个常见的问题。这可以说也是网站的头号安全漏洞。此外，将过滤器和验证器分散在整个应用程序中可能会相当尴尬。链接机制将整洁地解决这些问题，并且还允许您控制过滤器和验证器处理的顺序。

## 如何做...

1.  有一个鲜为人知的 PHP 函数`filter_input_array()`，乍一看似乎非常适合这个任务。然而，深入了解其功能后，很快就会发现这个函数是在早期设计的，并不符合对抗攻击和灵活性的现代要求。因此，我们将提出一个基于执行过滤和验证的回调数组的更加灵活的机制。

### 注意

*过滤*和*验证*之间的区别在于，过滤可能会删除或转换值。另一方面，验证使用与数据性质相适应的标准测试数据，并返回布尔结果。

1.  为了增加灵活性，我们将使我们的基本过滤器和验证类相对轻量。这意味着*不*定义任何特定的过滤器或验证方法。相反，我们将完全基于回调的配置数组进行操作。为了确保过滤和验证结果的兼容性，我们还将定义一个特定的结果对象`Application\Filter\Result`。

1.  `Result`类的主要功能将是保存`$item`值，这将是过滤后的值或验证的布尔结果。另一个属性`$messages`将保存在过滤或验证操作期间填充的消息数组。在构造函数中，为`$messages`提供的值被制定为一个数组。您可能会注意到这两个属性都被定义为`public`。这是为了方便访问：

```php
namespace Application\Filter;

class Result
{

  public $item;  // (mixed) filtered data | (bool) result of validation
  public $messages = array();  // [(string) message, (string) message ]

  public function __construct($item, $messages)
  {
    $this->item = $item;
    if (is_array($messages)) {
        $this->messages = $messages;
    } else {
        $this->messages = [$messages];
    }
  }
```

1.  我们还定义了一种方法，允许我们将这个`Result`实例与另一个实例合并。这很重要，因为在某个时候，我们将通过一系列过滤器处理相同的值。在这种情况下，我们希望新过滤的值覆盖现有的值，但希望消息被合并：

```php
public function mergeResults(Result $result)
{
  $this->item = $result->item;
  $this->mergeMessages($result);
}

public function mergeMessages(Result $result)
{
  if (isset($result->messages) && is_array($result->messages)) {
    $this->messages = array_merge($this->messages, $result->messages);
  }
}
```

1.  最后，为了完成这个类的方法，我们添加了一个合并验证结果的方法。这里需要考虑的重要问题是，*任何*值为`FALSE`，无论是在验证链上还是下来，都必须导致*整个*结果为`FALSE`：

```php
public function mergeValidationResults(Result $result)
{
  if ($this->item === TRUE) {
    $this->item = (bool) $result->item;
  }
  $this->mergeMessages($result);
  }

}
```

1.  接下来，为了确保回调产生兼容的结果，我们将定义一个`Application\Filter\CallbackInterface`接口。您会注意到我们正在利用 PHP 7 能够对返回值进行数据类型化，以确保我们得到一个`Result`实例作为返回值：

```php
namespace Application\Filter;
interface CallbackInterface
{
  public function __invoke ($item, $params) : Result;
}
```

1.  每个回调应引用相同的消息集。因此，我们使用`Application\Filter\Messages`类定义了一系列静态属性。我们提供了设置所有消息或只设置一个消息的方法。`$messages`属性已经被设置为`public`以便更容易访问：

```php
namespace Application\Filter;
class Messages
{
  const MESSAGE_UNKNOWN = 'Unknown';
  public static $messages;
  public static function setMessages(array $messages)
  {
    self::$messages = $messages;
  }
  public static function setMessage($key, $message)
  {
    self::$messages[$key] = $message;
  }
  public static function getMessage($key)
  {
    return self::$messages[$key] ?? self::MESSAGE_UNKNOWN;
  }
}
```

1.  现在，我们可以定义一个实现核心功能的`Application\Web\AbstractFilter`类。如前所述，这个类将相对*轻量级*，我们不需要担心特定的过滤器或验证器，因为它们将通过配置提供。我们使用`UnexpectedValueException`类，作为 PHP 7 **标准 PHP 库**（**SPL**）的一部分，以便在其中一个回调没有实现`CallbackInterface`时抛出一个描述性异常：

```php
namespace Application\Filter;
use UnexpectedValueException;
abstract class AbstractFilter
{
  // code described in the next several bullets
```

1.  首先，我们定义了一些有用的类常量，其中包含各种*管理*值。这里显示的最后四个控制要显示的消息格式，以及如何描述*缺失*数据：

```php
const BAD_CALLBACK = 'Must implement CallbackInterface';
const DEFAULT_SEPARATOR = '<br>' . PHP_EOL;
const MISSING_MESSAGE_KEY = 'item.missing';
const DEFAULT_MESSAGE_FORMAT = '%20s : %60s';
const DEFAULT_MISSING_MESSAGE = 'Item Missing';
```

1.  接下来，我们定义了核心属性。`$separator`与过滤和验证消息一起使用。`$callbacks`表示执行过滤和验证的回调数组。`$assignments`将数据字段映射到过滤器和/或验证器。`$missingMessage`表示为属性，以便可以覆盖它（即用于多语言网站）。最后，`$results`是一个`Application\Filter\Result`对象数组，并由过滤或验证操作填充：

```php
protected $separator;    // used for message display
protected $callbacks;
protected $assignments;
protected $missingMessage;
protected $results = array();
```

1.  在这一点上，我们可以构建`__construct()`方法。它的主要功能是设置回调和赋值的数组。它还设置值或接受分隔符（用于消息显示）和*missing*消息的默认值：

```php
public function __construct(array $callbacks, array $assignments, 
                            $separator = NULL, $message = NULL)
{
  $this->setCallbacks($callbacks);
  $this->setAssignments($assignments);
  $this->setSeparator($separator ?? self::DEFAULT_SEPARATOR);
  $this->setMissingMessage($message 
                           ?? self::DEFAULT_MISSING_MESSAGE);
}
```

1.  接下来，我们定义了一系列方法，允许我们设置或移除回调。请注意，我们允许获取和设置单个回调。如果您有一组通用的回调，并且只需要修改一个回调，这将非常有用。您还会注意到`setOneCall()`检查回调是否实现了`CallbackInterface`。如果没有，将抛出`UnexpectedValueException`：

```php
public function getCallbacks()
{
  return $this->callbacks;
}

public function getOneCallback($key)
{
  return $this->callbacks[$key] ?? NULL;
}

public function setCallbacks(array $callbacks)
{
  foreach ($callbacks as $key => $item) {
    $this->setOneCallback($key, $item);
  }
}

public function setOneCallback($key, $item)
{
  if ($item instanceof CallbackInterface) {
      $this->callbacks[$key] = $item;
  } else {
      throw new UnexpectedValueException(self::BAD_CALLBACK);
  }
}

public function removeOneCallback($key)
{
  if (isset($this->callbacks[$key])) 
  unset($this->callbacks[$key]);
}
```

1.  结果处理的方法非常简单。为了方便起见，我们添加了`getItemsAsArray()`，否则`getResults()`将返回一个`Result`对象数组：

```php
public function getResults()
{
  return $this->results;
}

public function getItemsAsArray()
{
  $return = array();
  if ($this->results) {
    foreach ($this->results as $key => $item) 
    $return[$key] = $item->item;
  }
  return $return;
}
```

1.  检索消息只是循环遍历`$this ->results`数组并提取`$messages`属性。为了方便起见，我们还添加了`getMessageString()`，其中包含一些格式选项。为了轻松生成消息数组，我们使用了 PHP 7 的`yield from`语法。这使得`getMessages()`成为一个**委托生成器**。消息数组成为一个**子生成器**：

```php
public function getMessages()
{
  if ($this->results) {
      foreach ($this->results as $key => $item) 
      if ($item->messages) yield from $item->messages;
  } else {
      return array();
  }
}

public function getMessageString($width = 80, $format = NULL)
{
  if (!$format)
  $format = self::DEFAULT_MESSAGE_FORMAT . $this->separator;
  $output = '';
  if ($this->results) {
    foreach ($this->results as $key => $value) {
      if ($value->messages) {
        foreach ($value->messages as $message) {
          $output .= sprintf(
            $format, $key, trim($message));
        }
      }
    }
  }
  return $output;
}
```

1.  最后，我们定义一组有用的 getter 和 setter：

```php
  public function setMissingMessage($message)
  {
    $this->missingMessage = $message;
  }
  public function setSeparator($separator)
  {
    $this->separator = $separator;
  }
  public function getSeparator()
  {
    return $this->separator;
  }
  public function getAssignments()
  {
    return $this->assignments;
  }
  public function setAssignments(array $assignments)
  {
    $this->assignments = $assignments;
  }
  // closing bracket for class AbstractFilter
}
```

1.  过滤和验证，虽然经常一起执行，但同样经常分开执行。因此，我们为每个定义离散的类。我们将从`Application\Filter\Filter`开始。我们使这个类扩展`AbstractFilter`，以提供先前描述的核心功能：

```php
namespace Application\Filter;
class Filter extends AbstractFilter
{
  // code
}
```

1.  在这个类中，我们定义了一个核心的`process()`方法，它扫描数据数组并根据分配数组应用过滤器。如果对这个数据集没有分配过滤器，我们只需返回`NULL`：

```php
public function process(array $data)
{
  if (!(isset($this->assignments) 
      && count($this->assignments))) {
        return NULL;
  }
```

1.  否则，我们将`$this->results`初始化为一个`Result`对象数组，其中`$item`属性是来自`$data`的原始值，`$messages`属性是一个空数组：

```php
foreach ($data as $key => $value) {
  $this->results[$key] = new Result($value, array());
}
```

1.  然后，我们复制`$this->assignments`并检查是否有任何*全局*过滤器（由'`*`'键标识）。如果有，我们运行`processGlobal()`然后取消'`*`'键：

```php
$toDo = $this->assignments;
if (isset($toDo['*'])) {
  $this->processGlobalAssignment($toDo['*'], $data);
  unset($toDo['*']);
}
```

1.  最后，我们循环遍历任何剩余的分配，调用`processAssignment()`：

```php
foreach ($toDo as $key => $assignment) {
  $this->processAssignment($assignment, $key);
}
```

1.  正如您所记得的，每个*assignment*都是针对数据字段的键，并表示该字段的回调数组。因此，在`processGlobalAssignment()`中，我们需要循环遍历回调数组。然而，在这种情况下，因为这些分配是*全局*的，我们还需要循环遍历*整个*数据集，并依次应用每个全局过滤器：

```php
protected function processGlobalAssignment($assignment, $data)
{
  foreach ($assignment as $callback) {
    if ($callback === NULL) continue;
    foreach ($data as $k => $value) {
      $result = $this->callbacks[$callback['key']]($this->results[$k]->item,
      $callback['params']);
      $this->results[$k]->mergeResults($result);
    }
  }
}
```

### 注意

棘手的部分是这行代码：

```php
$result = $this->callbacks[$callback['key']]($this ->results[$k]->item, $callback['params']);
```

记住，每个回调实际上是一个匿名类，定义了 PHP 魔术`__invoke()`方法。提供的参数是要过滤的实际数据项和参数数组。通过运行`$this->callbacks[$callback['key']]()`，我们实际上是在神奇地调用`__invoke()`。

1.  当我们定义`processAssignment()`时，类似于`processGlobalAssignment()`的方式，我们需要执行分配给每个数据键的每个剩余回调：

```php
  protected function processAssignment($assignment, $key)
  {
    foreach ($assignment as $callback) {
      if ($callback === NULL) continue;
      $result = $this->callbacks[$callback['key']]($this->results[$key]->item, 
                                 $callback['params']);
      $this->results[$key]->mergeResults($result);
    }
  }
}  // closing brace for Application\Filter\Filter
```

### 注意

任何改变原始用户提供的数据的过滤操作都应显示一个消息，指示已进行更改，这可以成为审计跟踪的一部分，以保护您免受潜在的法律责任，当更改在用户不知情或未经同意的情况下进行时。

## 它是如何工作的...

创建一个`Application\Filter`文件夹。在这个文件夹中，使用前面步骤中的代码创建以下类文件：

| Application\Filter\*类文件 | 在这些步骤中描述的代码 |
| --- | --- |
| `Result.php` | 3 - 5 |
| `CallbackInterface.php` | 6 |
| `Messages.php` | 7 |
| `AbstractFilter.php` | 8 - 15 |
| `Filter.php` | 16 - 22 |

接下来，获取步骤 5 中讨论的代码，并将其用于在`chap_06_post_data_config_messages.php`文件中配置消息数组。每个回调引用`Messages::$messages`属性。以下是一个示例配置：

```php
<?php
use Application\Filter\Messages;
Messages::setMessages(
  [
    'length_too_short' => 'Length must be at least %d',
    'length_too_long'  => 'Length must be no more than %d',
    'required'         => 'Please be sure to enter a value',
    'alnum'            => 'Only letters and numbers allowed',
    'float'            => 'Only numbers or decimal point',
    'email'            => 'Invalid email address',
    'in_array'         => 'Not found in the list',
    'trim'             => 'Item was trimmed',
    'strip_tags'       => 'Tags were removed from this item',
    'filter_float'     => 'Converted to a decimal number',
    'phone'            => 'Phone number is [+n] nnn-nnn-nnnn',
    'test'             => 'TEST',
    'filter_length'    => 'Reduced to specified length',
  ]
);
```

接下来，创建一个`chap_06_post_data_config_callbacks.php`回调配置文件，其中包含过滤回调的配置，如步骤 4 中所述。每个回调应遵循这个通用模板：

```php
'callback_key' => new class () implements CallbackInterface 
{
  public function __invoke($item, $params) : Result
  {
    $changed  = array();
    $filtered = /* perform filtering operation on $item */
    if ($filtered !== $item) $changed = Messages::$messages['callback_key'];
    return new Result($filtered, $changed);
  }
}
```

回调本身必须实现接口并返回一个`Result`实例。我们可以利用 PHP 7 的**匿名类**功能，让我们的回调返回一个实现`CallbackInterface`的匿名类。以下是一个过滤回调数组可能的样子：

```php
use Application\Filter\ { Result, Messages, CallbackInterface };
$config = [ 'filters' => [
  'trim' => new class () implements CallbackInterface 
  {
    public function __invoke($item, $params) : Result
    {
      $changed  = array();
      $filtered = trim($item);
      if ($filtered !== $item) 
      $changed = Messages::$messages['trim'];
      return new Result($filtered, $changed);
    }
  },
  'strip_tags' => new class () 
  implements CallbackInterface 
  {
    public function __invoke($item, $params) : Result
    {
      $changed  = array();
      $filtered = strip_tags($item);
      if ($filtered !== $item)     
      $changed = Messages::$messages['strip_tags'];
      return new Result($filtered, $changed);
    }
  },
  // etc.
]
];
```

为了测试目的，我们将使用 prospects 表作为目标。我们将构建一个*好*和*坏*数据的数组，而不是从`$_POST`提供数据：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_06_10.jpg)

现在，您可以创建一个`chap_06_post_data_filtering.php`脚本，设置自动加载，包括消息和回调配置文件：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
include __DIR__ . '/chap_06_post_data_config_messages.php';
include __DIR__ . '/chap_06_post_data_config_callbacks.php';
```

然后，您需要定义*assignments*，表示数据字段和过滤回调之间的映射关系。使用`*`键来定义适用于所有数据的*全局*过滤器：

```php
$assignments = [
  '*'   => [ ['key' => 'trim', 'params' => []], 
          ['key' => 'strip_tags', 'params' => []] ],
  'first_name'  => [ ['key' => 'length', 
   'params' => ['length' => 128]] ],
  'last_name'  => [ ['key' => 'length', 
   'params' => ['length' => 128]] ],
  'city'          => [ ['key' => 'length', 
   'params' => ['length' => 64]] ],
  'budget'     => [ ['key' => 'filter_float', 'params' => []] ],
];
```

接下来，定义*好*和*坏*的测试数据：

```php
$goodData = [
  'first_name'      => 'Your Full',
  'last_name'       => 'Name',
  'address'         => '123 Main Street',
  'city'            => 'San Francisco',
  'state_province'  => 'California',
  'postal_code'     => '94101',
  'phone'           => '+1 415-555-1212',
  'country'         => 'US',
  'email'           => 'your@email.address.com',
  'budget'          => '123.45',
];
$badData = [
  'first_name'      => 'This+Name<script>bad tag</script>Valid!',
  'last_name'       => 'ThisLastNameIsWayTooLongAbcdefghijklmnopqrstuvwxyz0123456789Abcdefghijklmnopqrstuvwxyz0123456789Abcdefghijklmnopqrstuvwxyz0123456789Abcdefghijklmnopqrstuvwxyz0123456789',
  //'address'       => '',    // missing
  'city'            => '  ThisCityNameIsTooLong012345678901234567890123456789012345678901234567890123456789  ',
  //'state_province'=> '',    // missing
  'postal_code'     => '!"£$%^Non Alpha Chars',
  'phone'           => ' 12345 ',
  'country'         => 'XX',
  'email'           => 'this.is@not@an.email',
  'budget'          => 'XXX',
];
```

最后，您可以创建一个`Application\Filter\Filter`实例，并测试数据：

```php
$filter = new Application\Filter\Filter(
$config['filters'], $assignments);
$filter->setSeparator(PHP_EOL);
  $filter->process($goodData);
echo $filter->getMessageString();
  var_dump($filter->getItemsAsArray());

$filter->process($badData);
echo $filter->getMessageString();
var_dump($filter->getItemsAsArray());
```

处理*好*的数据除了指示*float*字段的值从字符串转换为`float`之外，不会产生任何消息。另一方面，*坏*的数据产生以下输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_06_11.jpg)

您还会注意到`first_name`中的标记已被移除，并且`last_name`和`city`都被截断。

## 还有更多...

`filter_input_array()`函数接受两个参数：输入源（以预定义的常量形式表示`$_*` PHP 超全局变量之一，即`$_POST`），以及匹配字段定义的数组作为键和过滤器或验证器作为值。此函数不仅执行过滤操作，还执行验证操作。标记为*sanitize*的标志实际上是过滤器。

## 另请参阅

可以在[`php.net/manual/en/function.filter-input-array.php`](http://php.net/manual/en/function.filter-input-array.php)找到`filter_input_array()`的文档和示例。您还可以查看[`php.net/manual/en/filter.filters.php`](http://php.net/manual/en/filter.filters.php)上可用的不同类型的*过滤器*。

# 将$_POST 验证器链接在一起

这个示例的*重要工作*已经在前面的示例中完成。核心功能由`Application\Filter\AbstractFilter`定义。实际的验证是由一系列验证回调执行的。

## 如何做...

1.  查看前面的示例，*链接$_POST 过滤器*。我们将在这个示例中使用所有的类和配置文件，除非在这里另有说明。

1.  首先，我们定义一个验证回调的配置数组。与前面的示例一样，每个回调都应实现`Application\Filter\CallbackInterface`，并应返回`Application\Filter\Result`的实例。验证器将采用这种通用形式：

```php
use Application\Filter\ { Result, Messages, CallbackInterface };
$config = [
  // validator callbacks
  'validators' => [
    'key' => new class () implements CallbackInterface 
    {
      public function __invoke($item, $params) : Result
      {
        // validation logic goes here
        return new Result($valid, $error);
      }
    },
    // etc.
```

1.  接下来，我们定义了一个`Application\Filter\Validator`类，它循环遍历赋值数组，测试每个数据项是否符合其分配的验证器回调。我们使这个类扩展`AbstractFilter`，以提供先前描述的核心功能：

```php
namespace Application\Filter;
class Validator extends AbstractFilter
{
  // code
}
```

1.  在这个类中，我们定义了一个核心的`process()`方法，它扫描数据数组并根据赋值数组应用验证器。如果对于这个数据集没有分配验证器，我们只需返回`$valid`的当前状态（即`TRUE`）：

```php
public function process(array $data)
{
  $valid = TRUE;
  if (!(isset($this->assignments) 
      && count($this->assignments))) {
        return $valid;
  }
```

1.  否则，我们将`$this->results`初始化为一个`Result`对象数组，其中`$item`属性设置为`TRUE`，`$messages`属性为空数组：

```php
foreach ($data as $key => $value) {
  $this->results[$key] = new Result(TRUE, array());
}
```

1.  然后，我们复制`$this->assignments`并检查是否有*全局*过滤器（由'`*`'键标识）。如果有，我们运行`processGlobal()`，然后取消'`*`'键：

```php
$toDo = $this->assignments;
if (isset($toDo['*'])) {
  $this->processGlobalAssignment($toDo['*'], $data);
  unset($toDo['*']);
}
```

1.  最后，我们循环遍历任何剩余的赋值，调用`processAssignment()`。这是一个理想的地方，用来检查赋值数组中是否缺少数据中存在的任何字段。请注意，如果任何验证回调返回`FALSE`，我们将`$valid`设置为`FALSE`：

```php
foreach ($toDo as $key => $assignment) {
  if (!isset($data[$key])) {
      $this->results[$key] = 
      new Result(FALSE, $this->missingMessage);
  } else {
      $this->processAssignment(
        $assignment, $key, $data[$key]);
  }
  if (!$this->results[$key]->item) $valid = FALSE;
  }
  return $valid;
}
```

1.  正如您所记得的，每个*赋值*都与数据字段相关联，并表示该字段的回调数组。因此，在`processGlobalAssignment()`中，我们需要循环遍历回调数组。然而，在这种情况下，因为这些赋值是*全局*的，我们还需要循环遍历*整个*数据集，并依次应用每个全局过滤器。

1.  与等效的`Application\Filter\Fiter::processGlobalAssignment()`方法相比，我们需要调用`mergeValidationResults()`。原因是，如果`$result->item`的值已经是`FALSE`，我们需要确保它不会随后被`TRUE`的值覆盖。链中返回`FALSE`的任何验证器都必须覆盖任何其他验证结果：

```php
protected function processGlobalAssignment($assignment, $data)
{
  foreach ($assignment as $callback) {
    if ($callback === NULL) continue;
    foreach ($data as $k => $value) {
      $result = $this->callbacks[$callback['key']]
      ($value, $callback['params']);
      $this->results[$k]->mergeValidationResults($result);
    }
  }
}
```

1.  当我们定义`processAssignment()`时，类似于`processGlobalAssignment()`，我们需要执行分配给每个数据键的每个剩余回调，再次调用`mergeValidationResults()`：

```php
protected function processAssignment($assignment, $key, $value)
{
  foreach ($assignment as $callback) {
    if ($callback === NULL) continue;
        $result = $this->callbacks[$callback['key']]
       ($value, $callback['params']);
        $this->results[$key]->mergeValidationResults($result);
    }
  }
```

## 它是如何工作的...

与前面的配方一样，请确保定义以下类：

+   `Application\Filter\Result`

+   `Application\Filter\CallbackInterface`

+   `Application\Filter\Messages`

+   `Application\Filter\AbstractFilter`

您可以使用前一配方中描述的`chap_06_post_data_config_messages.php`文件。

接下来，在`Application\Filter`文件夹中创建一个`Validator.php`文件。放置步骤 3 到 10 中描述的代码。

接下来，创建一个包含验证回调配置的`chap_06_post_data_config_callbacks.php`回调配置文件，如步骤 2 中描述的那样。每个回调应遵循这个通用模板：

```php
'validation_key' => new class () implements CallbackInterface 
{
  public function __invoke($item, $params) : Result
  {
    $error = array();
    $valid = /* perform validation operation on $item */
    if (!$valid) 
    $error[] = Messages::$messages['validation_key'];
    return new Result($valid, $error);
  }
}
```

现在，您可以创建一个`chap_06_post_data_validation.php`调用脚本，该脚本初始化自动加载并包含配置脚本：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
include __DIR__ . '/chap_06_post_data_config_messages.php';
include __DIR__ . '/chap_06_post_data_config_callbacks.php';
```

接下来，定义一个分配数组，将数据字段映射到验证器回调键：

```php
$assignments = [
  'first_name'       => [ ['key' => 'length',  
  'params'   => ['min' => 1, 'max' => 128]], 
                ['key' => 'alnum',   
  'params'   => ['allowWhiteSpace' => TRUE]],
                ['key'   => 'required','params' => []] ],
  'last_name'=> [ ['key' => 'length',  
  'params'   => ['min'   => 1, 'max' => 128]],
                ['key'   => 'alnum',   
  'params'   => ['allowWhiteSpace' => TRUE]],
                ['key'   => 'required','params' => []] ],
  'address'       => [ ['key' => 'length',  
  'params'        => ['max' => 256]] ],
  'city'          => [ ['key' => 'length',  
  'params'        => ['min' => 1, 'max' => 64]] ], 
  'state_province'=> [ ['key' => 'length',  
  'params'        => ['min' => 1, 'max' => 32]] ], 
  'postal_code'   => [ ['key' => 'length',  
  'params'        => ['min' => 1, 'max' => 16] ], 
                     ['key' => 'alnum',   
  'params'        => ['allowWhiteSpace' => TRUE]],
                     ['key' => 'required','params' => []] ],
  'phone'         => [ ['key' => 'phone', 'params' => []] ],
  'country'       => [ ['key' => 'in_array',
  'params'        => $countries ], 
                     ['key' => 'required','params' => []] ],
  'email'         => [ ['key' => 'email', 'params' => [] ],
                     ['key' => 'length',  
  'params'        => ['max' => 250] ], 
                     ['key' => 'required','params' => [] ] ],
  'budget'        => [ ['key' => 'float', 'params' => []] ]
];
```

对于测试数据，请使用在前一配方中描述的`chap_06_post_data_filtering.php`文件中定义的相同的*good*和*bad*数据。之后，您可以创建一个`Application\Filter\Validator`实例，并测试数据：

```php
$validator = new Application\Filter\Validator($config['validators'], $assignments);
$validator->setSeparator(PHP_EOL);
$validator->process($badData);
echo $validator->getMessageString(40, '%14s : %-26s' . PHP_EOL);
var_dump($validator->getItemsAsArray());
$validator->process($goodData);
echo $validator->getMessageString(40, '%14s : %-26s' . PHP_EOL);
var_dump($validator->getItemsAsArray());
```

如预期的那样，*good*数据不会产生任何验证错误。另一方面，*bad*数据会生成以下输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_06_13.jpg)

请注意，*missing*字段`address`和`state_province`验证为`FALSE`，并返回缺少项目消息。

# 将验证与表单绑定

当表单首次呈现时，将表单类（如前一配方中描述的`Application\Form\Factory`）与可以执行过滤或验证的类（如前一配方中描述的`Application\Filter\*`）绑定是没有太大价值的。但是，一旦表单数据被提交，兴趣就增加了。如果表单数据未通过验证，可以对值进行过滤，然后重新显示。验证错误消息可以与表单元素绑定，并在表单字段旁边呈现。

## 如何做...

1.  首先，确保实现*实现表单工厂*、*链接$_POST 过滤器*和*链接$_POST 验证器*配方中定义的类。

1.  现在，我们将注意力转向`Application\Form\Factory`类，并添加属性和 setter，允许我们附加`Application\Filter\Filter`和`Application\Filter\Validator`的实例。我们还需要定义`$data`，用于保留过滤和/或验证的数据：

```php
const DATA_NOT_FOUND = 'Data not found. Run setData()';
const FILTER_NOT_FOUND = 'Filter not found. Run setFilter()';
const VALIDATOR_NOT_FOUND = 'Validator not found. Run setValidator()';

protected $filter;
protected $validator;
protected $data;

public function setFilter(Filter $filter)
{
  $this->filter = $filter;
}

public function setValidator(Validator $validator)
{
  $this->validator = $validator;
}

public function setData($data)
{
  $this->data = $data;
}
```

1.  接下来，我们定义一个`validate()`方法，该方法调用嵌入的`Application\Filter\Validator`实例的`process()`方法。我们检查`$data`和`$validator`是否存在。如果不存在，将抛出适当的异常，并提供哪个方法需要首先运行的说明：

```php
public function validate()
{
  if (!$this->data)
  throw new RuntimeException(self::DATA_NOT_FOUND);

  if (!$this->validator)
  throw new RuntimeException(self::VALIDATOR_NOT_FOUND);
```

1.  调用`process()`方法后，我们将验证结果消息与表单元素消息关联起来。请注意，`process()`方法返回一个布尔值，表示数据集的整体验证状态。当表单在验证失败后重新显示时，错误消息将出现在每个元素旁边：

```php
$valid = $this->validator->process($this->data);

foreach ($this->elements as $element) {
  if (isset($this->validator->getResults()
      [$element->getName()])) {
        $element->setErrors($this->validator->getResults()
        [$element->getName()]->messages);
      }
    }
    return $valid;
  }
```

1.  类似地，我们定义了一个`filter()`方法，该方法调用嵌入的`Application\Filter\Filter`实例的`process()`方法。与步骤 3 中描述的`validate()`方法一样，我们需要检查`$data`和`$filter`的存在。如果缺少任一项，我们将抛出一个带有适当消息的`RuntimeException`：

```php
public function filter()
{
  if (!$this->data)
  throw new RuntimeException(self::DATA_NOT_FOUND);

  if (!$this->filter)
  throw new RuntimeException(self::FILTER_NOT_FOUND);
```

1.  然后我们运行`process()`方法，该方法生成一个`Result`对象数组，其中`$item`属性表示过滤器链的最终结果。然后我们遍历结果，如果相应的`$element`键匹配，将`value`属性设置为过滤后的值。我们还添加了过滤过程中产生的任何消息。然后重新显示表单时，所有值属性都将显示过滤后的结果：

```php
$this->filter->process($this->data);
foreach ($this->filter->getResults() as $key => $result) {
  if (isset($this->elements[$key])) {
    $this->elements[$key]
    ->setSingleAttribute('value', $result->item);
    if (isset($result->messages) 
        && count($result->messages)) {
      foreach ($result->messages as $message) {
        $this->elements[$key]->addSingleError($message);
      }
    }
  }      
}
}
```

## 它是如何工作的...

您可以从对`Application\Form\Factory`进行上述更改开始。作为测试目标，您可以使用*如何工作...*部分中显示的潜在客户数据库表的内容。各种列设置应该让您了解要定义哪些表单元素、过滤器和验证器。

例如，您可以定义一个`chap_06_tying_filters_to_form_definitions.php`文件，其中包含表单包装、元素和过滤器分配的定义。以下是一些示例：

```php
<?php
use Application\Form\Generic;

define('VALIDATE_SUCCESS', 'SUCCESS: form submitted ok!');
define('VALIDATE_FAILURE', 'ERROR: validation errors detected');

$wrappers = [
  Generic::INPUT  => ['type' => 'td', 'class' => 'content'],
  Generic::LABEL  => ['type' => 'th', 'class' => 'label'],
  Generic::ERRORS => ['type' => 'td', 'class' => 'error']
];

$elements = [
  'first_name' => [  
     'class'     => 'Application\Form\Generic',
     'type'      => Generic::TYPE_TEXT, 
     'label'     => 'First Name', 
     'wrappers'  => $wrappers,
     'attributes'=> ['maxLength'=>128,'required'=>'']
  ],
  'last_name'   => [  
    'class'     => 'Application\Form\Generic',
    'type'      => Generic::TYPE_TEXT, 
    'label'     => 'Last Name', 
    'wrappers'  => $wrappers,
    'attributes'=> ['maxLength'=>128,'required'=>'']
  ],
    // etc.
];

// overall form config
$formConfig = [ 
  'name'       => 'prospectsForm',
  'attributes' => [
'method'=>'post',
'action'=>'chap_06_tying_filters_to_form.php'
],
  'row_wrapper'  => ['type' => 'tr', 'class' => 'row'],
  'form_wrapper' => [
    'type'=>'table',
    'class'=>'table',
    'id'=>'prospectsTable',
    'class'=>'display','cellspacing'=>'0'
  ],
  'form_tag_inside_wrapper' => FALSE,
];

$assignments = [
  'first_name'    => [ ['key' => 'length',  
  'params'        => ['min' => 1, 'max' => 128]], 
                     ['key' => 'alnum',   
  'params'        => ['allowWhiteSpace' => TRUE]],
                     ['key' => 'required','params' => []] ],
  'last_name'     => [ ['key' => 'length',  
  'params'        => ['min' => 1, 'max' => 128]],
                     ['key' => 'alnum',   
  'params'        => ['allowWhiteSpace' => TRUE]],
                     ['key' => 'required','params' => []] ],
  'address'       => [ ['key' => 'length',  
  'params'        => ['max' => 256]] ],
  'city'          => [ ['key' => 'length',  
  'params'        => ['min' => 1, 'max' => 64]] ], 
  'state_province'=> [ ['key' => 'length',  
  'params'        => ['min' => 1, 'max' => 32]] ], 
  'postal_code'   => [ ['key' => 'length',  
  'params'        => ['min' => 1, 'max' => 16] ], 
                     ['key' => 'alnum',   
  'params'        => ['allowWhiteSpace' => TRUE]],
                     ['key' => 'required','params' => []] ],
  'phone'         => [ ['key' => 'phone',   'params' => []] ],
  'country'       => [ ['key' => 'in_array',
  'params'        => $countries ], 
                     ['key' => 'required','params' => []] ],
  'email'         => [ ['key' => 'email',   'params' => [] ],
                     ['key' => 'length',  
  'params'        => ['max' => 250] ], 
                     ['key' => 'required','params' => [] ] ],
  'budget'        => [ ['key' => 'float',   'params' => []] ]
];
```

您可以使用先前配方中描述的已经存在的`chap_06_post_data_config_callbacks.php`和`chap_06_post_data_config_messages.php`文件。最后，定义一个`chap_06_tying_filters_to_form.php`文件，设置自动加载并包含这三个配置文件：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
include __DIR__ . '/chap_06_post_data_config_messages.php';
include __DIR__ . '/chap_06_post_data_config_callbacks.php';
include __DIR__ . '/chap_06_tying_filters_to_form_definitions.php';
```

接下来，您可以创建表单工厂、过滤器和验证器类的实例：

```php
use Application\Form\Factory;
use Application\Filter\ { Validator, Filter };
$form = Factory::generate($elements);
$form->setFilter(new Filter($callbacks['filters'], $assignments['filters']));
$form->setValidator(new Validator($callbacks['validators'], $assignments['validators']));
```

然后，您可以检查是否有任何`$_POST`数据。如果有，执行验证和过滤：

```php
$message = '';
if (isset($_POST['submit'])) {
  $form->setData($_POST);
  if ($form->validate()) {
    $message = VALIDATE_SUCCESS;
  } else {
    $message = VALIDATE_FAILURE;
  }
  $form->filter();
}
?>
```

视图逻辑非常简单：只需呈现表单。任何验证消息和各种元素的值都将作为验证和过滤的一部分分配：

```php
  <?= $form->render($form, $formConfig); ?>
```

这是一个使用不良表单数据的示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_06_14.jpg)

注意过滤和验证消息。还要注意不良标签：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_06_15.jpg)


# 第七章：访问 Web 服务

在本章中，我们将涵盖以下主题：

+   在 PHP 和 XML 之间进行转换

+   创建一个简单的 REST 客户端

+   创建一个简单的 REST 服务器

+   创建一个简单的 SOAP 客户端

+   创建一个简单的 SOAP 服务器

# 介绍

向外部 Web 服务进行后台查询正成为任何 PHP Web 实践的日益重要的一部分。提供适当、及时和丰富的数据意味着为您的客户和您开发的网站带来更多的业务。我们首先介绍了一些旨在在**可扩展标记语言**（**XML**）和本机 PHP 之间进行数据转换的配方。接下来，我们将向您展示如何实现一个简单的**表述状态转移**（**REST**）客户端和服务器。之后，我们将把注意力转向**SOAP**客户端和服务器。

# 在 PHP 和 XML 之间进行转换

在考虑 PHP 本机数据类型和 XML 之间的转换时，我们通常将数组视为主要目标。基于此，从 PHP 数组转换为 XML 的过程与需要执行相反操作的方法有很大的不同。

### 注意

对象也可以考虑进行转换；然而，将对象方法呈现为 XML 是困难的。属性可以通过使用`get_object_vars()`函数来表示，该函数将对象属性读入数组中。

## 如何做...

1.  首先，我们定义一个`Application\Parse\ConvertXml`类。这个类将包含将从 XML 转换为 PHP 数组，反之亦然的方法。我们将需要 SPL 中的`SimpleXMLElement`和`SimpleXMLIterator`类：

```php
namespace Application\Parse;
use SimpleXMLIterator;
use SimpleXMLElement;
class ConvertXml
{
}
```

1.  接下来，我们定义一个`xmlToArray()`方法，它将接受一个`SimpleXMLIterator`实例作为参数。它将被递归调用，并将从 XML 文档生成一个 PHP 数组。我们利用`SimpleXMLIterator`能够通过 XML 文档前进的能力，使用`key()`、`current()`、`next()`和`rewind()`方法进行导航：

```php
public function xmlToArray(SimpleXMLIterator $xml) : array
{
  $a = array();
  for( $xml->rewind(); $xml->valid(); $xml->next() ) {
    if(!array_key_exists($xml->key(), $a)) {
      $a[$xml->key()] = array();
    }
    if($xml->hasChildren()){
      $a[$xml->key()][] = $this->xmlToArray($xml->current());
    }
    else{
      $a[$xml->key()] = (array) $xml->current()->attributes();
      $a[$xml->key()]['value'] = strval($xml->current());
    }
  }
  return $a;
}
```

1.  对于相反的过程，也称为递归，我们定义了两种方法。第一种方法`arrayToXml()`设置了一个初始的`SimpleXMLElement`实例，然后调用第二种方法`phpToXml()`：

```php
public function arrayToXml(array $a)
{
  $xml = new SimpleXMLElement(
  '<?xml version="1.0" standalone="yes"?><root></root>');
  $this->phpToXml($a, $xml);
  return $xml->asXML();
}
```

1.  请注意，在第二种方法中，我们使用`get_object_vars()`，以防数组元素是对象。您还会注意到，单独的数字不允许作为 XML 标签，这意味着在数字前面添加一些文本：

```php
protected function phpToXml($value, &$xml)
{
  $node = $value;
  if (is_object($node)) {
    $node = get_object_vars($node);
  }
  if (is_array($node)) {
    foreach ($node as $k => $v) {
      if (is_numeric($k)) {
        $k = 'number' . $k;
      }
      if (is_array($v)) {
          $newNode = $xml->addChild($k);
          $this->phpToXml($v, $newNode);
      } elseif (is_object($v)) {
          $newNode = $xml->addChild($k);
          $this->phpToXml($v, $newNode);
      } else {
          $xml->addChild($k, $v);
      }
    }
  } else  {
      $xml->addChild(self::UNKNOWN_KEY, $node);
  }
}
```

## 它是如何工作的...

作为一个示例 XML 文档，您可以使用美国国家气象局的**Web 服务定义语言**（**WSDL**）。这是一个描述 SOAP 服务的 XML 文档，可以在[`graphical.weather.gov/xml/SOAP_server/ndfdXMLserver.php?wsdl`](http://graphical.weather.gov/xml/SOAP_server/ndfdXMLserver.php?wsdl)找到。

我们将使用`SimpleXMLIterator`类来提供迭代机制。然后，您可以配置自动加载，并使用`xmlToArray()`获取`Application\Parse\ConvertXml`的实例，将 WSDL 转换为 PHP 数组：

```php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Parse\ConvertXml;
$wsdl = 'http://graphical.weather.gov/xml/'
. 'SOAP_server/ndfdXMLserver.php?wsdl';
$xml = new SimpleXMLIterator($wsdl, 0, TRUE);
$convert = new ConvertXml();
var_dump($convert->xmlToArray($xml));
```

结果数组显示如下：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_07_01.jpg)

要执行相反的操作，请使用本配方中描述的`arrayToXml()`方法。作为源文档，您可以使用一个包含通过 O'Reilly Media 提供的 MongoDB 培训视频大纲的`source/data/mongo.db.global.php`文件（免责声明：由本作者提供！）。使用相同的自动加载程序配置和`Application\Parse\ConvertXml`的实例，这是您可以使用的示例代码：

```php
$convert = new ConvertXml();
header('Content-Type: text/xml');
echo $convert->arrayToXml(include CONFIG_FILE);
```

这是在浏览器中的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_07_02.jpg)

# 创建一个简单的 REST 客户端

REST 客户端使用**超文本传输协议**（**HTTP**）向外部 Web 服务生成请求。通过更改 HTTP 方法，我们可以导致外部服务执行不同的操作。虽然有很多可用的方法（或动词），但我们只关注`GET`和`POST`。在这个配方中，我们将使用**适配器**软件设计模式来呈现实现 REST 客户端的两种不同方式。

## 如何做...

1.  在我们定义 REST 客户端适配器之前，我们需要定义用于表示请求和响应信息的通用类。首先，我们将从一个抽象类开始，该类具有请求或响应所需的方法和属性：

```php
namespace Application\Web;

class AbstractHttp
{
```

1.  接下来，我们定义代表 HTTP 信息的类常量：

```php
const METHOD_GET = 'GET';
const METHOD_POST = 'POST';
const METHOD_PUT = 'PUT';
const METHOD_DELETE = 'DELETE';
const CONTENT_TYPE_HTML = 'text/html';
const CONTENT_TYPE_JSON = 'application/json';
const CONTENT_TYPE_FORM_URL_ENCODED = 
  'application/x-www-form-urlencoded';
const HEADER_CONTENT_TYPE = 'Content-Type';
const TRANSPORT_HTTP = 'http';
const TRANSPORT_HTTPS = 'https';
const STATUS_200 = '200';
const STATUS_401 = '401';
const STATUS_500 = '500';
```

1.  然后，我们定义了请求或响应所需的属性：

```php
protected $uri;      // i.e. http://xxx.com/yyy
protected $method;    // i.e. GET, PUT, POST, DELETE
protected $headers;  // HTTP headers
protected $cookies;  // cookies
protected $metaData;  // information about the transmission
protected $transport;  // i.e. http or https
protected $data = array();
```

1.  逻辑上，我们需要为这些属性定义 getter 和 setter：

```php
public function setMethod($method)
{
  $this->method = $method;
}
public function getMethod()
{
  return $this->method ?? self::METHOD_GET;
}
// etc.
```

1.  有些属性需要通过键访问。为此，我们定义了`getXxxByKey()`和`setXxxByKey()`方法：

```php
public function setHeaderByKey($key, $value)
{
  $this->headers[$key] = $value;
}
public function getHeaderByKey($key)
{
  return $this->headers[$key] ?? NULL;
}
public function getDataByKey($key)
{
  return $this->data[$key] ?? NULL;
}
public function getMetaDataByKey($key)
{
  return $this->metaData[$key] ?? NULL;
}
```

1.  在某些情况下，请求将需要参数。我们假设参数将以 PHP 数组的形式存储在`$data`属性中。然后我们可以使用`http_build_query()`函数构建请求 URL：

```php
public function setUri($uri, array $params = NULL)
{
  $this->uri = $uri;
  $first = TRUE;
  if ($params) {
    $this->uri .= '?' . http_build_query($params);
  }
}
public function getDataEncoded()
{
  return http_build_query($this->getData());
}
```

1.  最后，我们根据原始请求设置`$transport`：

```php
public function setTransport($transport = NULL)
{
  if ($transport) {
      $this->transport = $transport;
  } else {
      if (substr($this->uri, 0, 5) == self::TRANSPORT_HTTPS) {
          $this->transport = self::TRANSPORT_HTTPS;
      } else {
          $this->transport = self::TRANSPORT_HTTP;
      }
    }
  }
```

1.  在这个示例中，我们将定义一个`Application\Web\Request`类，当我们希望生成一个请求时，可以接受参数，或者在实现接受请求的服务器时，可以填充属性与传入的请求信息：

```php
namespace Application\Web;
class Request extends AbstractHttp
{
  public function __construct(
    $uri = NULL, $method = NULL, array $headers = NULL, 
    array $data = NULL, array $cookies = NULL)
    {
      if (!$headers) $this->headers = $_SERVER ?? array();
      else $this->headers = $headers;
      if (!$uri) $this->uri = $this->headers['PHP_SELF'] ?? '';
      else $this->uri = $uri;
      if (!$method) $this->method = 
        $this->headers['REQUEST_METHOD'] ?? self::METHOD_GET;
      else $this->method = $method;
      if (!$data) $this->data = $_REQUEST ?? array();
      else $this->data = $data;
      if (!$cookies) $this->cookies = $_COOKIE ?? array();
      else $this->cookies = $cookies;
      $this->setTransport();
    }  
}
```

1.  现在我们可以转向响应类。在这种情况下，我们将定义一个`Application\Web\Received`类。这个名称反映了我们正在重新打包从外部网络服务接收到的数据的事实：

```php
namespace Application\Web;
class Received extends AbstractHttp
{
  public function __construct(
    $uri = NULL, $method = NULL, array $headers = NULL, 
    array $data = NULL, array $cookies = NULL)
  {
    $this->uri = $uri;
    $this->method = $method;
    $this->headers = $headers;
    $this->data = $data;
    $this->cookies = $cookies;
    $this->setTransport();
  }  
}
```

### 创建基于流的 REST 客户端

我们现在准备考虑两种不同的实现 REST 客户端的方式。第一种方法是使用一个称为**Streams**的底层 PHP I/O 层。这一层提供了一系列包装器，用于访问外部流资源。默认情况下，任何 PHP 文件命令都将使用文件包装器，这使得可以访问本地文件系统。我们将使用`http://`或`https://`包装器来实现`Application\Web\Client\Streams`适配器：

1.  首先，我们定义一个`Application\Web\Client\Streams`类：

```php
namespace Application\Web\Client;
use Application\Web\ { Request, Received };
class Streams
{
  const BYTES_TO_READ = 4096;
```

1.  接下来，我们定义一个方法来将请求发送到外部网络服务。在`GET`的情况下，我们将参数添加到 URI 中。在`POST`的情况下，我们创建一个包含元数据的流上下文，指示远程服务我们正在提供数据。使用 PHP Streams，发出请求只是简单地组合 URI，在`POST`的情况下设置流上下文。然后我们使用一个简单的`fopen()`：

```php
public static function send(Request $request)
{
  $data = $request->getDataEncoded();
  $received = new Received();
  switch ($request->getMethod()) {
    case Request::METHOD_GET :
      if ($data) {
        $request->setUri($request->getUri() . '?' . $data);
      }
      $resource = fopen($request->getUri(), 'r');
      break;
    case Request::METHOD_POST :
      $opts = [
        $request->getTransport() => 
        [
          'method'  => Request::METHOD_POST,
          'header'  => Request::HEADER_CONTENT_TYPE 
          . ': ' . Request::CONTENT_TYPE_FORM_URL_ENCODED,
          'content' => $data
        ]
      ];
      $resource = fopen($request->getUri(), 'w', 
      stream_context_create($opts));
      break;
    }
    return self::getResults($received, $resource);
}
```

1.  最后，我们将看一下如何将结果检索并打包成一个`Received`对象。您会注意到我们添加了一个解码以 JSON 格式接收数据的规定：

```php
protected static function getResults(Received $received, $resource)
{
  $received->setMetaData(stream_get_meta_data($resource));
  $data = $received->getMetaDataByKey('wrapper_data');
  if (!empty($data) && is_array($data)) {
    foreach($data as $item) {
      if (preg_match('!^HTTP/\d\.\d (\d+?) .*?$!', 
          $item, $matches)) {
          $received->setHeaderByKey('status', $matches[1]);
      } else {
          list($key, $value) = explode(':', $item);
          $received->setHeaderByKey($key, trim($value));
      }
    }
  }
  $payload = '';
  while (!feof($resource)) {
    $payload .= fread($resource, self::BYTES_TO_READ);
  }
  if ($received->getHeaderByKey(Received::HEADER_CONTENT_TYPE)) {
    switch (TRUE) {
      case stripos($received->getHeaderByKey(
                   Received::HEADER_CONTENT_TYPE), 
                   Received::CONTENT_TYPE_JSON) !== FALSE:
        $received->setData(json_decode($payload));
        break;
      default :
        $received->setData($payload);
        break;
          }
    }
    return $received;
}
```

### 定义基于 cURL 的 REST 客户端

我们现在将看一下我们的第二种 REST 客户端的方法，其中之一是基于 cURL 扩展的：

1.  对于这种方法，我们将假设相同的请求和响应类。初始类定义与之前讨论的 Streams 客户端基本相同：

```php
namespace Application\Web\Client;
use Application\Web\ { Request, Received };
class Curl
{
```

1.  `send()`方法比使用 Streams 时要简单得多。我们所需要做的就是定义一个选项数组，然后让 cURL 来处理剩下的事情：

```php
public static function send(Request $request)
{
  $data = $request->getDataEncoded();
  $received = new Received();
  switch ($request->getMethod()) {
    case Request::METHOD_GET :
      $uri = ($data) 
        ? $request->getUri() . '?' . $data 
        : $request->getUri();
          $options = [
            CURLOPT_URL => $uri,
            CURLOPT_HEADER => 0,
            CURLOPT_RETURNTRANSFER => TRUE,
            CURLOPT_TIMEOUT => 4
          ];
          break;
```

1.  `POST`需要稍有不同的 cURL 参数：

```php
case Request::METHOD_POST :
  $options = [
    CURLOPT_POST => 1,
    CURLOPT_HEADER => 0,
    CURLOPT_URL => $request->getUri(),
    CURLOPT_FRESH_CONNECT => 1,
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_FORBID_REUSE => 1,
    CURLOPT_TIMEOUT => 4,
    CURLOPT_POSTFIELDS => $data
  ];
  break;
}
```

1.  然后，我们执行一系列 cURL 函数，并通过`getResults()`运行结果：

```php
$ch = curl_init();
curl_setopt_array($ch, ($options));
if( ! $result = curl_exec($ch))
{
  trigger_error(curl_error($ch));
}
$received->setMetaData(curl_getinfo($ch));
curl_close($ch);
return self::getResults($received, $result);
}
```

1.  `getResults()`方法将结果打包成一个`Received`对象：

```php
protected static function getResults(Received $received, $payload)
{
  $type = $received->getMetaDataByKey('content_type');
  if ($type) {
    switch (TRUE) {
      case stripos($type, 
          Received::CONTENT_TYPE_JSON) !== FALSE):
          $received->setData(json_decode($payload));
          break;
      default :
          $received->setData($payload);
          break;
    }
  }
  return $received;
}
```

## 工作原理...

确保将所有前面的代码复制到这些类中：

+   `Application\Web\AbstractHttp`

+   `Application\Web\Request`

+   `Application\Web\Received`

+   `Application\Web\Client\Streams`

+   `Application\Web\Client\Curl`

在这个示例中，您可以向 Google Maps API 发出 REST 请求，以获取两个点之间的驾驶路线。您还需要按照[`developers.google.com/maps/documentation/directions/get-api-key`](https://developers.google.com/maps/documentation/directions/get-api-key)上的说明创建一个 API 密钥。

然后，您可以定义一个`chap_07_simple_rest_client_google_maps_curl.php`调用脚本，使用`Curl`客户端发出请求。您还可以考虑定义一个`chap_07_simple_rest_client_google_maps_streams.php`调用脚本，使用`Streams`客户端发出请求：

```php
<?php
define('DEFAULT_ORIGIN', 'New York City');
define('DEFAULT_DESTINATION', 'Redondo Beach');
define('DEFAULT_FORMAT', 'json');
$apiKey = include __DIR__ . '/google_api_key.php';
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Web\Request;
use Application\Web\Client\Curl;
```

然后您可以获取起点和目的地：

```php
$start = $_GET['start'] ?? DEFAULT_ORIGIN;
$end   = $_GET['end'] ?? DEFAULT_DESTINATION;
$start = strip_tags($start);
$end   = strip_tags($end);
```

现在，您可以填充`Request`对象，并使用它来生成请求：

```php
$request = new Request(
  'https://maps.googleapis.com/maps/api/directions/json',
  Request::METHOD_GET,
  NULL,
  ['origin' => $start, 'destination' => $end, 'key' => $apiKey],
  NULL
);

$received = Curl::send($request);
$routes   = $received->getData()->routes[0];
include __DIR__ . '/chap_07_simple_rest_client_google_maps_template.php';
```

为了说明的目的，您还可以定义一个表示视图逻辑的模板，以显示请求结果：

```php
<?php foreach ($routes->legs as $item) : ?>
  <!-- Trip Info -->
  <br>Distance: <?= $item->distance->text; ?>
  <br>Duration: <?= $item->duration->text; ?>
  <!-- Driving Directions -->
  <table>
    <tr>
    <th>Distance</th><th>Duration</th><th>Directions</th>
    </tr>
    <?php foreach ($item->steps as $step) : ?>
    <?php $class = ($count++ & 01) ? 'color1' : 'color2'; ?>
    <tr>
    <td class="<?= $class ?>"><?= $step->distance->text ?></td>
    <td class="<?= $class ?>"><?= $step->duration->text ?></td>
    <td class="<?= $class ?>">
    <?= $step->html_instructions ?></td>
    </tr>
    <?php endforeach; ?>
  </table>
<?php endforeach; ?>
```

以下是在浏览器中看到的请求结果：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_07_03.jpg)

## 还有更多...

**PHP 标准建议**（**PSR-7**）精确地定义了在 PHP 应用程序之间进行请求时要使用的请求和响应对象。这在附录中有详细介绍，*定义 PSR-7 类*。

## 另请参阅

有关`Streams`的更多信息，请参阅此 PHP 文档页面[`php.net/manual/en/book.stream.php`](http://php.net/manual/en/book.stream.php)。一个经常被问到的问题是“HTTP PUT 和 POST 之间有什么区别？”关于这个话题的优秀讨论，请参考[`stackoverflow.com/questions/107390/whats-the-difference-between-a-post-and-a-put-http-request`](http://stackoverflow.com/questions/107390/whats-the-difference-between-a-post-and-a-put-http-request)。有关从 Google 获取 API 密钥的更多信息，请参考以下网页：

[`developers.google.com/maps/documentation/directions/get-api-key`](https://developers.google.com/maps/documentation/directions/get-api-key)

[`developers.google.com/maps/documentation/directions/intro#Introduction`](https://developers.google.com/maps/documentation/directions/intro#Introduction)

# 创建一个简单的 REST 服务器

在实现 REST 服务器时有几个考虑因素。回答这三个问题将让您定义 REST 服务：

+   如何捕获原始请求？

+   您想要发布什么**应用程序编程接口**（**API**）？

+   您打算如何将 HTTP 动词（例如`GET`、`PUT`、`POST`和`DELETE`）映射到 API 方法？

## 如何做...

1.  我们将通过构建在前一篇文章*创建一个简单的 REST 客户端*中定义的请求和响应类来实现我们的 REST 服务器。回顾前一篇文章中讨论的类，包括以下内容：

+   `Application\Web\AbstractHttp`

+   `Application\Web\Request`

+   `Application\Web\Received`

1.  我们还需要定义一个正式的`Application\Web\Response`响应类，基于`AbstractHttp`。这个类与其他类的主要区别在于它接受`Application\Web\Request`的实例作为参数。主要工作是在`__construct()`方法中完成的。设置`Content-Type`标头和状态也很重要：

```php
namespace Application\Web;
class Response extends AbstractHttp
{

  public function __construct(Request $request = NULL, 
                              $status = NULL, $contentType = NULL)
  {
    if ($request) {
      $this->uri = $request->getUri();
      $this->data = $request->getData();
      $this->method = $request->getMethod();
      $this->cookies = $request->getCookies();
      $this->setTransport();
    }
    $this->processHeaders($contentType);
    if ($status) {
      $this->setStatus($status);
    }
  }
  protected function processHeaders($contentType)
  {
    if (!$contentType) {
      $this->setHeaderByKey(self::HEADER_CONTENT_TYPE, 
        self::CONTENT_TYPE_JSON);
    } else {
      $this->setHeaderByKey(self::HEADER_CONTENT_TYPE, 
        $contentType);
    }
  }
  public function setStatus($status)
  {
    $this->status = $status;
  }
  public function getStatus()
  {
    return $this->status;
  }
}
```

1.  我们现在可以定义`Application\Web\Rest\Server`类。您可能会对它有多简单感到惊讶。真正的工作是在相关的 API 类中完成的：

### 注意

请注意 PHP 7 组使用语法的使用：

```php
use Application\Web\ { Request,Response,Received }
```

```php
namespace Application\Web\Rest;
use Application\Web\ { Request, Response, Received };
class Server
{
  protected $api;
  public function __construct(ApiInterface $api)
  {
    $this->api = $api;
  }
```

1.  接下来，我们定义一个`listen()`方法，作为请求的目标。服务器实现的核心是这行代码：

```php
$jsonData = json_decode(file_get_contents('php://input'),true);
```

1.  这捕获了假定为 JSON 格式的原始输入：

```php
public function listen()
{
  $request  = new Request();
  $response = new Response($request);
  $getPost  = $_REQUEST ?? array();
  $jsonData = json_decode(
    file_get_contents('php://input'),true);
  $jsonData = $jsonData ?? array();
  $request->setData(array_merge($getPost,$jsonData));
```

### 注意

我们还添加了身份验证的规定。否则，任何人都可以发出请求并获取潜在的敏感数据。您会注意到我们没有服务器类执行身份验证；相反，我们把它留给 API 类：

```php
if (!$this->api->authenticate($request)) {
    $response->setStatus(Request::STATUS_401);
    echo $this->api::ERROR;
    exit;
}
```

1.  然后将 API 方法映射到主要的 HTTP 方法`GET`、`PUT`、`POST`和`DELETE`：

```php
$id = $request->getData()[$this->api::ID_FIELD] ?? NULL;
switch (strtoupper($request->getMethod())) {
  case Request::METHOD_POST :
    $this->api->post($request, $response);
    break;
  case Request::METHOD_PUT :
    $this->api->put($request, $response);
    break;
  case Request::METHOD_DELETE :
    $this->api->delete($request, $response);
    break;
  case Request::METHOD_GET :
  default :
    // return all if no params
  $this->api->get($request, $response);
}
```

1.  最后，我们打包响应并发送它，以 JSON 编码：

```php
  $this->processResponse($response);
  echo json_encode($response->getData());
}
```

1.  `processResponse()`方法设置标头，并确保结果打包为`Application\Web\Response`对象：

```php
protected function processResponse($response)
{
  if ($response->getHeaders()) {
    foreach ($response->getHeaders() as $key => $value) {
      header($key . ': ' . $value, TRUE, 
             $response->getStatus());
    }
  }        
  header(Request::HEADER_CONTENT_TYPE 
  . ': ' . Request::CONTENT_TYPE_JSON, TRUE);
  if ($response->getCookies()) {
    foreach ($response->getCookies() as $key => $value) {
      setcookie($key, $value);
    }
  }
}
```

1.  如前所述，API 类完成了真正的工作。我们首先定义一个抽象类，确保主要方法`get()`，`put()`等都有对应的实现，并且所有这些方法都接受请求和响应对象作为参数。您可能会注意到我们添加了一个`generateToken()`方法，它使用 PHP 7 的`random_bytes()`函数生成一个真正随机的 16 字节序列：

```php
namespace Application\Web\Rest;
use Application\Web\ { Request, Response };
abstract class AbstractApi implements ApiInterface
{
  const TOKEN_BYTE_SIZE  = 16;
  protected $registeredKeys;
  abstract public function get(Request $request, 
                               Response $response);
  abstract public function put(Request $request, 
                               Response $response);
  abstract public function post(Request $request, 
                                Response $response);
  abstract public function delete(Request $request, 
                                  Response $response);
  abstract public function authenticate(Request $request);
  public function __construct($registeredKeys, $tokenField)
  {
    $this->registeredKeys = $registeredKeys;
  }
  public static function generateToken()
  {
    return bin2hex(random_bytes(self::TOKEN_BYTE_SIZE));    
  }
}
```

1.  我们还定义了一个相应的接口，可用于架构和设计目的，以及代码开发控制：

```php
namespace Application\Web\Rest;
use Application\Web\ { Request, Response };
interface ApiInterface
{
  public function get(Request $request, Response $response);
  public function put(Request $request, Response $response);
  public function post(Request $request, Response $response);
  public function delete(Request $request, Response $response);
  public function authenticate(Request $request);
}
```

1.  在这里，我们提供了一个基于`AbstractApi`的示例 API。这个类利用了在第五章中定义的数据库类，*与数据库交互*：

```php
namespace Application\Web\Rest;
use Application\Web\ { Request, Response, Received };
use Application\Entity\Customer;
use Application\Database\ { Connection, CustomerService };

class CustomerApi extends AbstractApi
{
  const ERROR = 'ERROR';
  const ERROR_NOT_FOUND = 'ERROR: Not Found';
  const SUCCESS_UPDATE = 'SUCCESS: update succeeded';
  const SUCCESS_DELETE = 'SUCCESS: delete succeeded';
  const ID_FIELD = 'id';      // field name of primary key
  const TOKEN_FIELD = 'token';  // field used for authentication
  const LIMIT_FIELD = 'limit';
  const OFFSET_FIELD = 'offset';
  const DEFAULT_LIMIT = 20;
  const DEFAULT_OFFSET = 0;

  protected $service;

  public function __construct($registeredKeys, 
                              $dbparams, $tokenField = NULL)
  {
    parent::__construct($registeredKeys, $tokenField);
    $this->service = new CustomerService(
      new Connection($dbparams));
  }
```

1.  所有方法都接收请求和响应作为参数。您会注意到使用`getDataByKey()`来检索数据项。实际的数据库交互是由服务类执行的。您可能还会注意到，在所有情况下，我们都设置了 HTTP 状态码来通知客户端成功或失败。在`get()`的情况下，我们会查找 ID 参数。如果收到，我们只提供有关单个客户的信息。否则，我们使用限制和偏移量提供所有客户的列表：

```php
public function get(Request $request, Response $response)
{
  $result = array();
  $id = $request->getDataByKey(self::ID_FIELD) ?? 0;
  if ($id > 0) {
      $result = $this->service->
        fetchById($id)->entityToArray();  
  } else {
    $limit  = $request->getDataByKey(self::LIMIT_FIELD) 
      ?? self::DEFAULT_LIMIT;
    $offset = $request->getDataByKey(self::OFFSET_FIELD) 
      ?? self::DEFAULT_OFFSET;
    $result = [];
    $fetch = $this->service->fetchAll($limit, $offset);
    foreach ($fetch as $row) {
      $result[] = $row;
    }
  }
  if ($result) {
      $response->setData($result);
      $response->setStatus(Request::STATUS_200);
  } else {
      $response->setData([self::ERROR_NOT_FOUND]);
      $response->setStatus(Request::STATUS_500);
  }
}
```

1.  `put()`方法用于插入客户数据：

```php
public function put(Request $request, Response $response)
{
  $cust = Customer::arrayToEntity($request->getData(), 
                                  new Customer());
  if ($newCust = $this->service->save($cust)) {
      $response->setData(['success' => self::SUCCESS_UPDATE, 
                          'id' => $newCust->getId()]);
      $response->setStatus(Request::STATUS_200);
  } else {
      $response->setData([self::ERROR]);
      $response->setStatus(Request::STATUS_500);
  }      
}
```

1.  `post()`方法用于更新现有的客户条目：

```php
public function post(Request $request, Response $response)
{
  $id = $request->getDataByKey(self::ID_FIELD) ?? 0;
  $reqData = $request->getData();
  $custData = $this->service->
    fetchById($id)->entityToArray();
  $updateData = array_merge($custData, $reqData);
  $updateCust = Customer::arrayToEntity($updateData, 
  new Customer());
  if ($this->service->save($updateCust)) {
      $response->setData(['success' => self::SUCCESS_UPDATE, 
                          'id' => $updateCust->getId()]);
      $response->setStatus(Request::STATUS_200);
  } else {
      $response->setData([self::ERROR]);
      $response->setStatus(Request::STATUS_500);
  }      
}
```

1.  如其名称所示，`delete()`会删除客户条目：

```php
public function delete(Request $request, Response $response)
{
  $id = $request->getDataByKey(self::ID_FIELD) ?? 0;
  $cust = $this->service->fetchById($id);
  if ($cust && $this->service->remove($cust)) {
      $response->setData(['success' => self::SUCCESS_DELETE, 
                          'id' => $id]);
      $response->setStatus(Request::STATUS_200);
  } else {
      $response->setData([self::ERROR_NOT_FOUND]);
      $response->setStatus(Request::STATUS_500);
  }
}
```

1.  最后，我们定义`authenticate()`来提供一个低级机制来保护 API 使用，例如在这个例子中：

```php
public function authenticate(Request $request)
{
  $authToken = $request->getDataByKey(self::TOKEN_FIELD) 
    ?? FALSE;
  if (in_array($authToken, $this->registeredKeys, TRUE)) {
      return TRUE;
  } else {
      return FALSE;
  }
}
}
```

## 它是如何工作的...

定义以下在前面的教程中讨论的类：

+   `Application\Web\AbstractHttp`

+   `Application\Web\Request`

+   `Application\Web\Received`

然后，您可以定义以下在本教程中描述的类，总结在下表中：

| 类 Application\Web\* | 在这些步骤中讨论 |
| --- | --- |
| `Response` | 2 |
| `Rest\Server` | 3 - 8 |
| `Rest\AbstractApi` | 9 |
| `Rest\ApiInterface` | 10 |
| `Rest\CustomerApi` | 11 - 16 |

现在您可以自由开发自己的 API 类。但是，如果您选择遵循示例`Application\Web\Rest\CustomerApi`，您还需要确保实现这些类，这些类在第五章中有介绍，*与数据库交互*：

+   `Application\Entity\Customer`

+   `Application\Database\Connection`

+   `Application\Database\CustomerService`

现在您可以定义一个`chap_07_simple_rest_server.php`脚本来调用 REST 服务器：

```php
<?php
$dbParams = include __DIR__ .  '/../../config/db.config.php';
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Web\Rest\Server;
use Application\Web\Rest\CustomerApi;
$apiKey = include __DIR__ . '/api_key.php';
$server = new Server(new CustomerApi([$apiKey], $dbParams, 'id'));
$server->listen();
```

然后，您可以使用内置的 PHP 7 开发服务器来监听端口`8080`以接收 REST 请求：

```php
**php -S localhost:8080 chap_07_simple_rest_server.php** 

```

要测试您的 API，可以使用`Application\Web\Rest\AbstractApi::generateToken()`方法生成一个认证令牌，然后将其放入一个`api_key.php`文件中，类似于这样：

```php
<?php return '79e9b5211bbf2458a4085707ea378129';
```

然后，您可以使用通用的 API 客户端（例如前面介绍的那种）或浏览器插件，比如 Chao Zhou 的 RESTClient（有关更多信息，请参见[`restclient.net/`](http://restclient.net/)）来生成示例请求。确保在请求中包含令牌，否则定义的 API 将拒绝请求。

这是一个基于`AbstractApi`的`POST`请求的示例，用于`ID`为`1`，将`balance`字段设置为`888888`的值：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_07_04.jpg)

## 还有更多...

有许多库可以帮助您实现 REST 服务器。我最喜欢的之一是一个在单个文件中实现 REST 服务器的示例：[`www.leaseweb.com/labs/2015/10/creating-a-simple-rest-api-in-php/`](https://www.leaseweb.com/labs/2015/10/creating-a-simple-rest-api-in-php/)

各种框架，如 CodeIgniter 和 Zend Framework，也有 REST 服务器实现。

# 创建一个简单的 SOAP 客户端

与实现 REST 客户端或服务器的过程相比，使用 SOAP 非常容易，因为有一个 PHP SOAP 扩展提供了这两种功能。

### 注意

一个经常被问到的问题是“SOAP 和 REST 之间有什么区别？” SOAP 在内部使用 XML 作为数据格式。SOAP 使用 HTTP 但仅用于传输，否则不了解其他 HTTP 方法。REST 直接操作 HTTP，并且可以使用任何数据格式，但首选 JSON。另一个关键区别是 SOAP 可以与 WSDL 一起操作，这使得服务自描述，因此更容易公开。因此，SOAP 服务通常由国家卫生组织等公共机构提供。

## 操作步骤...

在本例中，我们将为美国国家气象局提供的现有 SOAP 服务进行 SOAP 请求：

1.  首先要考虑的是识别**WSDL**文档。WSDL 是描述服务的 XML 文档：

```php
$wsdl = 'http://graphical.weather.gov/xml/SOAP_server/'
  . 'ndfdXMLserver.php?wsdl';
```

1.  接下来，我们使用 WSDL 创建一个`soap client`实例：

```php
$soap = new SoapClient($wsdl, array('trace' => TRUE));
```

1.  然后，我们可以自由地初始化一些变量，以期待天气预报请求：

```php
$units = 'm';
$params = '';
$numDays = 7;
$weather = '';
$format = '24 hourly';
$startTime = new DateTime();
```

1.  然后，我们可以进行`LatLonListCityNames()` SOAP 请求，该请求在 WSDL 中标识为一个操作，以获取服务支持的城市列表。请求以 XML 格式返回，这表明需要创建一个`SimpleXLMElement`实例：

```php
$xml = new SimpleXMLElement($soap->LatLonListCityNames(1));
```

1.  不幸的是，城市及其对应的纬度和经度列表在单独的 XML 节点中。因此，我们使用`array_combine()` PHP 函数创建一个关联数组，其中纬度/经度是键，城市名是值。然后，我们可以稍后使用这个数组来呈现 HTML `SELECT`下拉列表，使用`asort()`对列表进行按字母排序：

```php
$cityNames = explode('|', $xml->cityNameList);
$latLonCity = explode(' ', $xml->latLonList);
$cityLatLon = array_combine($latLonCity, $cityNames);
asort($cityLatLon);
```

1.  然后，我们可以按以下方式从 Web 请求中获取城市数据：

```php
$currentLatLon = (isset($_GET['city'])) ? strip_tags(urldecode($_GET['city'])) : '';
```

1.  我们希望进行的 SOAP 调用是`NDFDgenByDay()`。我们可以通过检查 WSDL 来确定提供给 SOAP 服务器的参数的性质：

```php
<message name="NDFDgenByDayRequest">
<part name="latitude" type="xsd:decimal"/>
<part name="longitude" type="xsd:decimal"/>
<part name="startDate" type="xsd:date"/>
<part name="numDays" type="xsd:integer"/>
<part name="Unit" type="xsd:string"/>
<part name="format" type="xsd:string"/>
</message>
```

1.  如果设置了`$currentLatLon`的值，我们可以处理请求。我们将请求包装在`try {} catch {}`块中，以防抛出任何异常：

```php
if ($currentLatLon) {
  list($lat, $lon) = explode(',', $currentLatLon);
  try {
      $weather = $soap->NDFDgenByDay($lat,$lon,
        $startTime->format('Y-m-d'),$numDays,$unit,$format);
  } catch (Exception $e) {
      $weather .= PHP_EOL;
      $weather .= 'Latitude: ' . $lat . ' | Longitude: ' . $lon;
      $weather .= 'ERROR' . PHP_EOL;
      $weather .= $e->getMessage() . PHP_EOL;
      $weather .= $soap->__getLastResponse() . PHP_EOL;
  }
}
?>
```

## 工作原理...

将所有前面的代码复制到`chap_07_simple_soap_client_weather_service.php`文件中。然后，您可以添加视图逻辑，显示带有城市列表的表单，以及结果：

```php
<form method="get" name="forecast">
<br> City List: 
<select name="city">
<?php foreach ($cityLatLon as $latLon => $city) : ?>
<?php $select = ($currentLatLon == $latLon) ? ' selected' : ''; ?>
<option value="<?= urlencode($latLon) ?>" <?= $select ?>>
<?= $city ?></option>
<?php endforeach; ?>
</select>
<br><input type="submit" value="OK"></td>
</form>
<pre>
<?php var_dump($weather); ?>
</pre>
```

以下是在浏览器中请求俄亥俄州克利夫兰天气预报的结果：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_07_05.jpg)

## 另请参阅

有关 SOAP 和 REST 之间的区别的讨论，请参阅[`stackoverflow.com/questions/209905/representational-state-transfer-rest-and-simple-object-access-protocol-soap?lq=1`](http://stackoverflow.com/questions/209905/representational-state-transfer-rest-and-simple-object-access-protocol-soap?lq=1)上的文章。

# 创建一个简单的 SOAP 服务器

与 SOAP 客户端一样，我们可以使用 PHP SOAP 扩展来实现 SOAP 服务器。实现中最困难的部分将是从 API 类生成 WSDL。我们在这里不涵盖该过程，因为有许多好的 WSDL 生成器可用。

## 操作步骤...

1.  首先，您需要一个 API，该 API 将由 SOAP 服务器处理。在本例中，我们定义了一个`Application\Web\Soap\ProspectsApi`类，允许我们创建、读取、更新和删除`prospects`表：

```php
namespace Application\Web\Soap;
use PDO;
class ProspectsApi
{
  protected $registerKeys;
  protected $pdo;

  public function __construct($pdo, $registeredKeys)
  {
    $this->pdo = $pdo;
    $this->registeredKeys = $registeredKeys;
  }
}
```

1.  然后，我们定义与创建、读取、更新和删除相对应的方法。在本例中，方法名为`put()`、`get()`、`post()`和`delete()`。这些方法依次调用生成 SQL 请求的方法，这些方法从 PDO 实例执行。`get()`的示例如下：

```php
public function get(array $request, array $response)
{
  if (!$this->authenticate($request)) return FALSE;
  $result = array();
  $id = $request[self::ID_FIELD] ?? 0;
  $email = $request[self::EMAIL_FIELD] ?? 0;
  if ($id > 0) {
      $result = $this->fetchById($id);  
      $response[self::ID_FIELD] = $id;
  } elseif ($email) {
      $result = $this->fetchByEmail($email);
      $response[self::ID_FIELD] = $result[self::ID_FIELD] ?? 0;
  } else {
      $limit = $request[self::LIMIT_FIELD] 
        ?? self::DEFAULT_LIMIT;
      $offset = $request[self::OFFSET_FIELD] 
        ?? self::DEFAULT_OFFSET;
      $result = [];
      foreach ($this->fetchAll($limit, $offset) as $row) {
        $result[] = $row;
      }
  }
  $response = $this->processResponse(
    $result, $response, self::SUCCESS, self::ERROR);
    return $response;
  }

  protected function processResponse($result, $response, 
                                     $success_code, $error_code)
  {
    if ($result) {
        $response['data'] = $result;
        $response['code'] = $success_code;
        $response['status'] = self::STATUS_200;
    } else {
        $response['data'] = FALSE;
        $response['code'] = self::ERROR_NOT_FOUND;
        $response['status'] = self::STATUS_500;
    }
    return $response;
  }
```

1.  然后，您可以从您的 API 生成 WSDL。有许多基于 PHP 的 WSDL 生成器可用（请参阅*还有更多...*部分）。大多数要求您在将要发布的方法之前添加`phpDocumentor`标签。在我们的示例中，两个参数都是数组。以下是先前讨论的 API 的完整 WSDL：

```php
<?xml version="1.0" encoding="UTF-8"?>
  <wsdl:definitions  targetNamespace="php7cookbook"    >
  <wsdl:message name="getSoapIn">
    <wsdl:part name="request" type="tns:array" />
    <wsdl:part name="response" type="tns:array" />
  </wsdl:message>
  <wsdl:message name="getSoapOut">
    <wsdl:part name="return" type="tns:array" />
  </wsdl:message>
  <!—some nodes removed to conserve space -->
  <wsdl:portType name="CustomerApiSoap">
  <!—some nodes removed to conserve space -->
  <wsdl:binding name="CustomerApiSoap" type="tns:CustomerApiSoap">
  <soap:binding transport="http://schemas.xmlsoap.org/soap/http" style="rpc" />
    <wsdl:operation name="get">
      <soap:operation soapAction="php7cookbook#get" />
        <wsdl:input>
          <soap:body use="encoded" encodingStyle= "http://schemas.xmlsoap.org/soap/encoding/" namespace="php7cookbook" parts="request response" />
        </wsdl:input>
        <wsdl:output>
          <soap:body use="encoded" encodingStyle= "http://schemas.xmlsoap.org/soap/encoding/" namespace="php7cookbook" parts="return" />
        </wsdl:output>
    </wsdl:operation>
  <!—some nodes removed to conserve space -->
  </wsdl:binding>
  <wsdl:service name="CustomerApi">
    <wsdl:port name="CustomerApiSoap" binding="tns:CustomerApiSoap">
    <soap:address location="http://localhost:8080/" />
    </wsdl:port>
  </wsdl:service>
  </wsdl:definitions>
```

1.  接下来，创建一个`chap_07_simple_soap_server.php`文件，用于执行 SOAP 服务器。首先定义 WSDL 的位置和任何其他必要的文件（在本例中，用于数据库配置的文件）。如果设置了`wsdl`参数，则提供 WSDL 而不是尝试处理请求。在这个例子中，我们使用一个简单的 API 密钥来验证请求。然后创建一个 SOAP 服务器实例，分配一个 API 类的实例，并运行`handle()`：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
define('WSDL_FILENAME', __DIR__ . '/chap_07_wsdl.xml');

if (isset($_GET['wsdl'])) {
    readfile(WSDL_FILENAME);
    exit;
}
$apiKey = include __DIR__ . '/api_key.php';
require __DIR__ . '/../Application/Web/Soap/ProspectsApi.php';
require __DIR__ . '/../Application/Database/Connection.php';
use Application\Database\Connection;
use Application\Web\Soap\ProspectsApi;
$connection = new Application\Database\Connection(
  include __DIR__ . DB_CONFIG_FILE);
$api = new Application\Web\Soap\ProspectsApi(
  $connection->pdo, [$apiKey]);
$server = new SoapServer(WSDL_FILENAME);
$server->setObject($api);
echo $server->handle();
```

### 注意

根据您的`php.ini`文件的设置，您可能需要禁用 WSDL 缓存，方法如下：

```php
ini_set('soap.wsdl_cache_enabled', 0);
```

如果您在处理传入的`POST`数据时遇到问题，可以按照以下方式调整此参数：

```php
ini_set('always_populate_raw_post_data', -1);
```

## 它是如何工作的...

您可以通过首先创建目标 API 类，然后生成 WSDL 来轻松测试此示例。然后，您可以使用内置的 PHP Web 服务器来提供 SOAP 服务，命令如下：

```php
**php -S localhost:8080 chap_07_simple_soap_server.php** 

```

然后，您可以使用前面讨论的 SOAP 客户端来调用测试 SOAP 服务：

```php
<?php
define('WSDL_URL', 'http://localhost:8080?wsdl=1');
$clientKey = include __DIR__ . '/api_key.php';
try {
  $client = new SoapClient(WSDL_URL);
  $response = [];
  $email = some_email_generated_by_test;
  $email = 'test5393@unlikelysource.com';
  echo "\nGet Prospect Info for Email: " . $email . "\n";
  $request = ['token' => $clientKey, 'email' => $email];
  $result = $client->get($request,$response);
  var_dump($result);

} catch (SoapFault $e) {
  echo 'ERROR' . PHP_EOL;
  echo $e->getMessage() . PHP_EOL;
} catch (Throwable $e) {
  echo 'ERROR' . PHP_EOL;
  echo $e->getMessage() . PHP_EOL;
} finally {
  echo $client->__getLastResponse() . PHP_EOL;
}
```

以下是电子邮件地址`test5393@unlikelysource.com`的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_07_06.jpg)

## 参见

简单地在谷歌上搜索 PHP 的 WSDL 生成器就会得到大约十几个结果。用于生成`ProspectsApi`类的 WSDL 的生成器基于[`code.google.com/archive/p/php-wsdl-creator/`](https://code.google.com/archive/p/php-wsdl-creator/)。有关`phpDocumentor`的更多信息，请参阅[`www.phpdoc.org/`](https://www.phpdoc.org/)页面。
