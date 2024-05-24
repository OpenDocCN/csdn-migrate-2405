# PHP7 编程秘籍（四）

> 原文：[`zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb`](https://zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：处理日期/时间和国际化方面

在本章中，我们将涵盖以下主题：

+   在视图脚本中使用表情符号或 emoji

+   转换复杂字符

+   从浏览器数据中获取 locale

+   按区域设置数字格式

+   按区域设置货币

+   按区域设置日期/时间格式

+   创建一个 HTML 国际日历生成器

+   构建重复事件生成器

+   处理翻译而无需 gettext

# 介绍

我们将从利用**PHP 7**引入的新**Unicode**转义语法开始本章的两个配方。之后，我们将介绍如何从浏览器数据中确定 Web 访问者的**locale**。接下来的几个配方将涵盖创建一个 locale 类，它将允许您以特定于 locale 的格式表示数字、货币、日期和时间。最后，我们将介绍一些演示如何生成国际化日历、处理重复事件和执行翻译的配方，而无需使用`gettext`。

# 在视图脚本中使用表情符号或 emoji

单词**emoticons**是*emotion*和*icon*的组合。**Emoji**源自日本，是另一个更大、更广泛使用的图标集。这些图标是小笑脸、小忍者和在地板上打滚大笑的图标，在任何具有社交网络方面的网站上都很受欢迎。然而，在 PHP 7 之前，制作这些小家伙是一种沮丧的练习。

## 如何做...

1.  首先，您需要知道您希望呈现的图标的 Unicode。在互联网上快速搜索将指引您到几个优秀的图表之一。以下是三个*hear-no-evil*，*see-no-evil*和*speak-no-evil*猴子图标的代码：

`U+1F648`，`U+1F649`和`U+1F64A`

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_11.jpg)

1.  向浏览器输出任何 Unicode 必须得到正确的标识。这通常是通过`meta`标签完成的。您应该将字符集设置为 UTF-8。以下是一个示例：

```php
<head>
  <title>PHP 7 Cookbook</title>
  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
</head>
```

1.  传统的方法是简单地使用 HTML 来显示图标。因此，您可以做如下操作：

```php
<table>
  <tr>
    <td>&#x1F648;</td>
    <td>&#x1F649;</td>
    <td>&#x1F64A;</td>
  </tr>
</table>
```

1.  从 PHP 7 开始，您现在可以使用此语法构造完整的 Unicode 字符：`"\u{xxx}"`。以下是与前述项目中相同的三个图标的示例：

```php
<table>
  <tr>
    <td><?php echo "\u{1F648}"; ?></td>
    <td><?php echo "\u{1F649}"; ?></td>
    <td><?php echo "\u{1F64A}"; ?></td>
  </tr>
</table>
```

### 注意

您的操作系统和浏览器都必须支持 Unicode，并且还必须具有正确的字体集。例如，在 Ubuntu Linux 中，您需要安装`ttf-ancient-fonts`软件包才能在浏览器中看到表情符号。

## 工作原理...

在 PHP 7 中，引入了一种新的语法，允许您呈现任何 Unicode 字符。与其他语言不同，新的 PHP 语法允许变量数量的十六进制数字。基本格式如下：

```php
\u{xxxx}
```

整个结构必须使用双引号引起来（或使用**heredoc**）。`xxxx`可以是任意组合的十六进制数字，2、4、6 及以上。

创建一个名为`chap_08_emoji_using_html.php`的文件。一定要包含`meta`标签，表示正在使用 UTF-8 字符编码的浏览器：

```php
<!DOCTYPE html>
<html>
  <head>
    <title>PHP 7 Cookbook</title>
    <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  </head>
```

接下来，设置一个基本的 HTML 表格，并显示一行表情符号/emoji：

```php
  <body>
    <table>
      <tr>
        <td>&#x1F648;</td>
        <td>&#x1F649;</td>
        <td>&#x1F64A;</td>
      </tr>
    </table>
  </body>
</html>
```

现在使用 PHP 添加一行以发出表情符号/emoji：

```php
  <tr>
    <td><?php echo "\u{1F648}"; ?></td>
    <td><?php echo "\u{1F649}"; ?></td>
    <td><?php echo "\u{1F64A}"; ?></td>
  </tr>
```

以下是从 Firefox 中看到的输出：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_01.jpg)

## 另请参阅

+   有关 emoji 代码的列表，请参阅[`unicode.org/emoji/charts/full-emoji-list.html`](http://unicode.org/emoji/charts/full-emoji-list.html)

# 转换复杂字符

访问整个 Unicode 字符集的能力为呈现复杂字符，特别是拉丁-1 字母表之外的字符，打开了许多新的可能性。

## 如何做...

1.  有些语言是从右到左而不是从左到右阅读的。例如希伯来语和阿拉伯语。在这个例子中，我们向您展示如何使用`U+202E` Unicode 字符来呈现*反向*文本。以下代码行打印`txet desreveR`：

```php
echo "\u{202E}Reversed text";
echo "\u{202D}";    // returns output to left-to-right
```

### 注意

完成后不要忘记调用从左到右覆盖字符`U+202D`！

1.  另一个考虑因素是使用组合字符。一个例子是`ñ`（字母`n`上面漂浮着一个波浪符`~`）。这在词语中使用，比如*mañana*（西班牙语中的早晨或明天，取决于上下文）。有一个*组合字符*，用 Unicode 代码`U+00F1`表示。这是它的使用示例，回显`mañana`：

```php
echo "ma\u{00F1}ana"; // shows mañana
```

1.  然而，这可能会影响搜索的可能性。想象一下，您的客户没有带有这个组合字符的键盘。如果他们开始输入`man`试图搜索`mañana`，他们将不成功。

1.  访问*完整*的 Unicode 集合提供了其他可能性。您可以使用*组合*字符，而不是使用*组合*字符，它可以在字母上方放置一个浮动的波浪符。在这个`echo`命令中，输出与以前相同。只是形成单词的方式不同：

```php
echo "man\u{0303}ana"; // also shows mañana
```

1.  类似的应用可以用于重音符号。考虑法语单词`élève`（学生）。您可以使用组合字符来呈现它，也可以使用组合代码将重音符号浮动在字母上方。考虑以下两个例子。这两个例子产生相同的输出，但呈现方式不同：

```php
echo "\u{00E9}l\u{00E8}ve";
echo "e\u{0301}le\u{0300}ve";
```

## 它是如何工作的...

创建一个名为`chap_08_control_and_combining_unicode.php`的文件。确保包含`meta`标签，表示正在使用 UTF-8 字符编码的浏览器：

```php
<!DOCTYPE html>
<html>
  <head>
    <title>PHP 7 Cookbook</title>
    <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  </head>
```

接下来，设置基本的 PHP 和 HTML 来显示之前讨论的示例：

```php
  <body>
    <pre>
      <?php
        echo "\u{202E}Reversed text"; // reversed
        //echo "\u{202D}"; // stops reverse
        echo "mañana";  // using pre-composed characters
        echo "ma\u{00F1}ana"; // pre-composed character
        echo "man\u{0303}ana"; // "n" with combining ~ character (U+0303)
        echo "élève";
        echo "\u{00E9}l\u{00E8}ve"; // pre-composed characters
        echo "e\u{0301}le\u{0300}ve"; // e + combining characters
      ?>
    </pre>
</body>
</html>
```

以下是浏览器的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_02.jpg)

# 从浏览器数据获取 locale

为了改善网站上的用户体验，重要的是以用户的区域设置可接受的格式显示信息。Locale 是一个通用术语，用来指示世界的某个地区。IT 社区已经努力使用由语言和国家代码组成的两部分指定来编码 locale。但是当一个人访问您的网站时，如何知道他们的区域设置呢？可能最有用的技术涉及检查 HTTP 语言标头。

## 如何做到...

1.  为了封装 locale 功能，我们将假设一个类`Application\I18n\Locale`。我们将使这个类扩展一个现有的类`Locale`，这是 PHP 的 Intl 扩展的一部分。

### 注意

I18n 是 Internationalization 的常见缩写。(计算字母的数量！)

```php
namespace Application\I18n;
use Locale as PhpLocale;
class Locale extends PhpLocale
{
  const FALLBACK_LOCALE = 'en';
  // some code
}
```

1.  为了了解传入请求的样子，使用`phpinfo(INFO_VARIABLES)`。在测试后立即禁用此功能，因为它会向潜在攻击者透露太多信息：

```php
<?php phpinfo(INFO_VARIABLES); ?>
```

1.  Locale 信息存储在`$_SERVER['HTTP_ACCEPT_LANGUAGE']`中。该值将采用这种一般形式：`ll-CC,rl;q=0.n, ll-CC,rl;q=0.n`，如表中所定义：

| 缩写 | 意义 |
| --- | --- |
| `ll` | 代表语言的两个小写字母代码。 |
| `-` | 在语言和国家之间分隔区域代码`ll-CC`。 |
| `CC` | 代表国家的两个大写字母代码。 |
| `,` | 将 locale 代码与回退**根 locale**代码（通常与语言代码相同）分隔开。 |
| `rl` | 代表建议的根 locale 的两个小写字母代码。 |
| `;` | 将 locale 信息与质量分隔开。如果质量丢失，默认为`q=1`（100%）概率；这是首选的。 |
| `q` | 质量。 |
| `0.n` | 0.00 到 1.0 之间的某个值。将此值乘以 100，以获得此访问者实际首选语言的概率百分比。 |

1.  可能会列出多个 locale。例如，网站访问者可能在他们的计算机上安装了多种语言。PHP 的 Locale 类恰好有一个方法`acceptFromHttp()`，它读取`Accept-language`标头字符串并给我们所需的设置：

```php
protected $localeCode;
public function setLocaleCode($acceptLangHeader)
{
  $this->localeCode = $this->acceptFromHttp($acceptLangHeader);
}
```

1.  然后我们可以定义适当的 getter。`get AcceptLanguage()`方法返回`$_SERVER['HTTP_ACCEPT_LANGUAGE']`中的值。

```php
public function getAcceptLanguage()
{
  return $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? self::FALLBACK_LOCALE;
}
public function getLocaleCode()
{
  return $this->localeCode;
}
```

1.  接下来，我们定义一个构造函数，允许我们“手动”设置区域设置。否则，区域设置信息将从浏览器中获取：

```php
public function __construct($localeString = NULL)
{
  if ($localeString) {
    $this->setLocaleCode($localeString);
  } else {
    $this->setLocaleCode($this->getAcceptLanguage());
  }
}
```

1.  现在要做出重要的决定：如何处理这些信息！这将在接下来的几篇文章中介绍。

### 注意

即使访问者似乎接受一个或多种语言，该访问者并不一定希望以其浏览器指示的语言/区域设置显示内容。因此，尽管您可以根据这些信息设置区域设置，但您还应该为他们提供一个静态的备选语言列表。

## 它是如何工作的...

在这个例子中，让我们举三个例子：

+   从浏览器获取的信息

+   预设区域设置`fr-FR`

+   从 RFC 2616 中获取的字符串：`da, en-gb;q=0.8, en;q=0.7`

将步骤 1 到 6 的代码放入一个名为`Locale.php`的文件中，该文件位于`Application\I18n`文件夹中。

接下来，创建一个名为`chap_08_getting_locale_from_browser.php`的文件，该文件设置自动加载并使用新的类：

```php
<?php
  require __DIR__ . '/../Application/Autoload/Loader.php';
  Application\Autoload\Loader::init(__DIR__ . '/..');
  use Application\I18n\Locale;
```

现在，您可以定义一个包含三个测试区域设置字符串的数组：

```php
$locale = [NULL, 'fr-FR', 'da, en-gb;q=0.8, en;q=0.7'];
```

最后，循环遍历三个区域设置字符串，创建新类的实例。回显从`getLocaleCode()`返回的值，以查看做出了什么选择：

```php
echo '<table>';
foreach ($locale as $code) {
  $locale = new Locale($code); 
  echo '<tr>
    <td>' . htmlspecialchars($code) . '</td>
    <td>' . $locale->getLocaleCode() . '</td>
  </tr>';
}
echo '</table>';
```

这是结果（稍微加了一点样式）：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_03.jpg)

## 另请参阅

+   有关 PHP`Locale`类的信息，请参阅[`php.net/manual/en/class.locale.php`](http://php.net/manual/en/class.locale.php)

+   有关`Accept-Language`标头的更多信息，请参阅 RFC 2616 的第 14.4 节：[`www.w3.org/Protocols/rfc2616/rfc2616-sec14.html`](https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html)

# 按区域设置格式化数字

数字表示可以根据区域设置而变化。举一个简单的例子，在英国，三百万八千五百一十二点九十二可以看作是：

```php
3,080,512.92.
```

然而，在法国，同样的数字可能会显示如下：

```php
3 080 512,92
```

## 如何做...

在表示特定区域的数字之前，您需要确定区域设置。这可以使用前面一篇文章中讨论的`Application\I18n\Locale`类来实现。区域设置可以手动设置或从标头信息中获取。

1.  接下来，我们将使用`NumberFormatter`类的`format()`方法，以区域特定的格式输出和解析数字。首先，我们添加一个属性，该属性将包含`NumberFormatter`类的一个实例：

```php
use NumberFormatter;
protected $numberFormatter;
```

### 注意

我们最初的想法是考虑使用 PHP 函数`setlocale()`根据区域设置生成格式化的数字。然而，这种传统方法的问题在于*一切*都将基于这个区域设置。这可能会引入处理根据数据库规范存储的数据的问题。`setlocale()`的另一个问题是它基于过时的标准，包括 RFC 1766 和 ISO 639。最后，`setlocale()`高度依赖于操作系统的区域支持，这将使我们的代码不可移植。

1.  通常，下一步将是在构造函数中设置`$numberFormatter`。然而，对于我们的`Application\I18n\Locale`类，这种方法的问题在于，我们最终会得到一个过于庞大的类，因为我们还需要执行货币和日期格式化。因此，我们添加一个`getter`，首先检查是否已经创建了`NumberFormatter`的实例。如果没有，则创建并返回一个实例。新的`NumberFormatter`中的第一个参数是区域代码。第二个参数`NumberFormatter::DECIMAL`表示我们需要的格式化类型：

```php
public function getNumberFormatter()
{
  if (!$this->numberFormatter) {
    $this->numberFormatter = new NumberFormatter($this->getLocaleCode(), NumberFormatter::DECIMAL);
  }
  return $this->numberFormatter;
}
```

1.  然后我们添加一个方法，给定任何数字，将生成一个字符串，该字符串根据区域设置格式化该数字：

```php
public function formatNumber($number)
{
  return $this->getNumberFormatter()->format($number);
}
```

1.  接下来，我们添加一个方法，该方法可用于根据区域设置解析数字，生成本机 PHP 数值。请注意，根据服务器的 ICU 版本，结果可能在解析失败时不会返回`FALSE`：

```php
public function parseNumber($string)
{
  $result = $this->getNumberFormatter()->parse($string);
  return ($result) ? $result : self::ERROR_UNABLE_TO_PARSE;
}
```

## 它是如何工作的...

按照前面的要点对`Application\I18n\Locale`类进行添加。然后，您可以创建一个`chap_08_formatting_numbers.php`文件，其中设置自动加载并使用此类：

```php
<?php
  require __DIR__ . '/../Application/Autoload/Loader.php';
  Application\Autoload\Loader::init(__DIR__ . '/..');
  use Application\I18n\Locale;
```

为此说明，创建两个`Locale`实例，一个用于英国，另一个用于法国。您还可以指定一个大数字用于测试：

```php
  $localeFr = new Locale('fr_FR');
  $localeUk = new Locale('en_GB');
  $number   = 1234567.89;
?>
```

最后，您可以将`formatNumber()`和`parseNumber()`方法包装在适当的 HTML 显示逻辑中，并查看结果：

```php
<!DOCTYPE html>
<html>
  <head>
    <title>PHP 7 Cookbook</title>
    <meta http-equiv="content-type" content="text/html;charset=utf-8" />
    <link rel="stylesheet" type="text/css" href="php7cookbook_html_table.css">
  </head>
  <body>
    <table>
      <tr>
        <th>Number</th>
        <td>1234567.89</td>
      </tr>
      <tr>
        <th>French Format</th>
        <td><?= $localeFr->formatNumber($number); ?></td>
      </tr>
      <tr>
        <th>UK Format</th>
        <td><?= $localeUk->formatNumber($number); ?></td>
      </tr>
      <tr>
        <th>UK Parse French Number: <?= $localeFr->formatNumber($number) ?></th>
        <td><?= $localeUk->parseNumber($localeFr->formatNumber($number)); ?></td>
      </tr>
      <tr>
        <th>UK Parse UK Number: <?= $localeUk->formatNumber($number) ?></th>
        <td><?= $localeUk->parseNumber($localeUk->formatNumber($number)); ?></td>
      </tr>
      <tr>
        <th>FR Parse FR Number: <?= $localeFr->formatNumber($number) ?></th>
        <td><?= $localeFr->parseNumber($localeFr->formatNumber($number)); ?></td>
      </tr>
      <tr>
        <th>FR Parse UK Number: <?= $localeUk->formatNumber($number) ?></th>
        <td><?= $localeFr->parseNumber($localeUk->formatNumber($number)); ?></td>
      </tr>
    </table>
  </body>
</html>
```

以下是从浏览器中看到的结果：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_04.jpg)

### 注意

请注意，如果区域设置为`fr_FR`，则解析时，以英国格式化的数字不会返回正确的值。同样，当区域设置为`en_GB`时，以法国格式化的数字在解析时也不会返回正确的值。因此，在尝试解析数字之前，您可能需要考虑添加验证检查。

## 另请参阅

+   有关使用和滥用`setlocale()`的更多信息，请参阅此页面：[`php.net/manual/en/function.setlocale.php`](http://php.net/manual/en/function.setlocale.php)。

+   关于为什么数字格式化在一些服务器上会产生错误，而在其他服务器上不会产生错误的简要说明，请查看**ICU**（**国际 Unicode 组件**）版本。请参阅此页面上的评论：[`php.net/manual/en/numberformatter.parse.php`](http://php.net/manual/en/numberformatter.parse.php)。有关 ICU 格式化的更多信息，请参见[`userguide.icu-project.org/formatparse`](http://userguide.icu-project.org/formatparse)。

# 按区域设置处理货币

处理货币的技术与处理数字的技术类似。我们甚至会使用相同的`NumberFormatter`类！然而，有一个主要区别，这是一个*停滞不前*的问题：为了正确格式化货币，您需要掌握货币代码。

## 如何做...

1.  首要任务是以某种格式使货币代码可用。一种可能性是将货币代码简单地添加为`Application\I18n\Locale`类的构造函数参数：

```php
const FALLBACK_CURRENCY = 'GBP';
protected $currencyCode;
public function __construct($localeString = NULL, $currencyCode = NULL)
{
  // add this to the existing code:
  $this->currencyCode = $currencyCode ?? self::FALLBACK_CURRENCY;
}
```

### 注意

尽管这种方法显然是可靠且可行的，但往往会属于*半途而废*或*走捷径*的范畴！这种方法也往往会消除完全自动化，因为货币代码无法从 HTTP 标头中获取。正如您可能从本书的其他示例中了解到的，我们不会回避更复杂的解决方案，所以，俗话说得好，*系好安全带*！

1.  我们首先需要建立某种查找机制，即给定一个国家代码，我们可以获取其主要货币代码。为此说明，我们将使用适配器软件设计模式。根据此模式，我们应该能够创建不同的类，这些类可能以完全不同的方式运行，但产生相同的结果。因此，我们需要定义所需的结果。为此目的，我们引入一个类，`Application\I18n\IsoCodes`。正如您所看到的，这个类具有所有相关的属性，以及一种类似通用的构造函数：

```php
namespace Application\I18n;
class IsoCodes
{
  public $name;
  public $iso2;
  public $iso3;
  public $iso_numeric;
  public $iso_3166;
  public $currency_name;
  public $currency_code;
  public $currency_number;
  public function __construct(array $data)
  {
    $vars = get_object_vars($this);
    foreach ($vars as $key => $value) {
      $this->$key = $data[$key] ?? NULL;
    }
  }
}
```

1.  接下来，我们定义一个接口，其中包含我们需要执行*国家代码到货币代码*查找的方法。在这种情况下，我们引入`Application\I18n\IsoCodesInterface`：

```php
namespace Application\I18n;

interface IsoCodesInterface
{
  public function getCurrencyCodeFromIso2CountryCode($iso2) : IsoCodes;
}
```

1.  现在我们准备构建一个查找适配器类，我们将其称为`Application\I18n\IsoCodesDb`。它实现了上述接口，并接受一个`Application\Database\Connection`实例（参见第一章，“建立基础”），用于执行查找。构造函数设置所需的信息，包括连接、查找表名称和表示 ISO2 代码的列。接口所需的查找方法然后发出一个 SQL 语句并返回一个数组，然后用于构建一个`IsoCodes`实例：

```php
namespace Application\I18n;

use PDO;
use Application\Database\Connection;

class IsoCodesDb implements IsoCodesInterface
{
  protected $isoTableName;
  protected $iso2FieldName;
  protected $connection;
  public function __construct(Connection $connection, $isoTableName, $iso2FieldName)
  {
    $this->connection = $connection;
    $this->isoTableName = $isoTableName;
    $this->iso2FieldName = $iso2FieldName;
  }
  public function getCurrencyCodeFromIso2CountryCode($iso2) : IsoCodes
  {
    $sql = sprintf('SELECT * FROM %s WHERE %s = ?', $this->isoTableName, $this->iso2FieldName);
    $stmt = $this->connection->pdo->prepare($sql);
    $stmt->execute([$iso2]);
    return new IsoCodes($stmt->fetch(PDO::FETCH_ASSOC);
  }
}
```

1.  现在我们将注意力转回到`Application\I18n\Locale`类。我们首先添加了一些新的属性和类常量：

```php
const ERROR_UNABLE_TO_PARSE = 'ERROR: Unable to parse';
const FALLBACK_CURRENCY = 'GBP';

protected $currencyFormatter;
protected $currencyLookup;
protected $currencyCode;
```

1.  我们添加了一个新的方法，从区域设置字符串中检索国家代码。我们可以利用来自 PHP`Locale`类（我们扩展的类）的“getRegion（）”方法。以防需要，我们还添加了一个“getCurrencyCode（）”方法：

```php
public function getCountryCode()
{
  return $this->getRegion($this->getLocaleCode());
}
public function getCurrencyCode()
{
  return $this->currencyCode;
}
```

1.  与格式化数字一样，我们定义了一个“getCurrencyFormatter（I）”，就像我们之前所做的“getNumberFormatter（）”一样。请注意，使用`NumberFormatter`定义了`$currencyFormatter`，但第二个参数不同：

```php
public function getCurrencyFormatter()
{
  if (!$this->currencyFormatter) {
    $this->currencyFormatter = new NumberFormatter($this->getLocaleCode(), NumberFormatter::CURRENCY);
  }
  return $this->currencyFormatter;
}
```

1.  然后，如果已定义查找类，我们将在类构造函数中添加货币代码查找：

```php
public function __construct($localeString = NULL, IsoCodesInterface $currencyLookup = NULL)
{
  // add this to the existing code:
  $this->currencyLookup = $currencyLookup;
  if ($this->currencyLookup) {
    $this->currencyCode = $this->currencyLookup->getCurrencyCodeFromIso2CountryCode($this->getCountryCode())->currency_code;
  } else {
    $this->currencyCode = self::FALLBACK_CURRENCY;
  }
}
```

1.  然后添加适当的货币格式和解析方法。请注意，与解析数字不同，如果解析操作不成功，解析货币将返回`FALSE`：

```php
public function formatCurrency($currency)
{
  return $this->getCurrencyFormatter()->formatCurrency($currency, $this->currencyCode);
}
public function parseCurrency($string)
{
  $result = $this->getCurrencyFormatter()->parseCurrency($string, $this->currencyCode);
  return ($result) ? $result : self::ERROR_UNABLE_TO_PARSE;
}
```

## 工作原理...

创建以下类，如前面几个要点中所述：

| 类 | 讨论的要点 |
| --- | --- |
| `Application\I18n\IsoCodes` | 3 |
| `Application\I18n\IsoCodesInterface` | 4 |
| `Application\I18n\IsoCodesDb` | 5 |

为了说明的目的，我们假设有一个填充了数据的 MySQL 数据库表`iso_country_codes`，其结构如下：

```php
CREATE TABLE `iso_country_codes` (
  `name` varchar(128) NOT NULL,
  `iso2` varchar(2) NOT NULL,
  `iso3` varchar(3) NOT NULL,
  `iso_numeric` int(11) NOT NULL AUTO_INCREMENT,
  `iso_3166` varchar(32) NOT NULL,
  `currency_name` varchar(32) DEFAULT NULL,
  `currency_code` char(3) DEFAULT NULL,
  `currency_number` int(4) DEFAULT NULL,
  PRIMARY KEY (`iso_numeric`)
) ENGINE=InnoDB AUTO_INCREMENT=895 DEFAULT CHARSET=utf8;
```

按照之前讨论的要点 6 到 9，对`Application\I18n\Locale`类进行添加。然后可以创建一个`chap_08_formatting_currency.php`文件，其中设置自动加载并使用适当的类：

```php
<?php
define('DB_CONFIG_FILE', __DIR__ . '/../config/db.config.php');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\I18n\Locale;
use Application\I18n\IsoCodesDb;
use Application\Database\Connection;
use Application\I18n\Locale;
```

接下来，我们创建`Connection`和`IsoCodesDb`类的实例：

```php
$connection = new Connection(include DB_CONFIG_FILE);
$isoLookup = new IsoCodesDb($connection, 'iso_country_codes', 'iso2');
```

为此示例，创建两个`Locale`实例，一个用于英国，另一个用于法国。您还可以指定一个大数字用于测试：

```php
$localeFr = new Locale('fr-FR', $isoLookup);
$localeUk = new Locale('en_GB', $isoLookup);
$number   = 1234567.89;
?>
```

最后，您可以将“formatCurrency（）”和“parseCurrency（）”方法包装在适当的 HTML 显示逻辑中，并查看结果。根据前一个配方中呈现的*工作原理...*部分（此处未重复以节省树木！）制定您的视图逻辑。这是最终输出：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_05.jpg)

## 参见

+   货币代码的最新列表由**ISO**（**国际标准化组织**）维护。您可以在**XML**或**XLS**（即**Microsoft Excel**电子表格格式）中获取此列表。以下是这些列表的页面：[`www.currency-iso.org/en/home/tables/table-a1.html`](http://www.currency-iso.org/en/home/tables/table-a1.html)。

# 按区域设置格式化日期/时间

日期和时间的格式因地区而异。作为一个经典的例子，考虑 2016 年，4 月，15 日和晚上的时间。美国人民偏好的格式可能是下午 7:23，2016 年 4 月 15 日，而在中国，您很可能会看到 2016-04-15 19:23。与数字和货币格式化一样，以一种对您的网站访问者可接受的格式显示（和解析）日期也很重要。

## 操作步骤...

1.  首先，我们需要修改`Application\I18n\Locale`，添加语句以使用日期格式化类：

```php
use IntlCalendar;
use IntlDateFormatter;
```

1.  接下来，我们添加一个属性来表示`IntlDateFormatter`实例，以及一系列预定义的常量：

```php
const DATE_TYPE_FULL   = IntlDateFormatter::FULL;
const DATE_TYPE_LONG   = IntlDateFormatter::LONG;
const DATE_TYPE_MEDIUM = IntlDateFormatter::MEDIUM;
const DATE_TYPE_SHORT  = IntlDateFormatter::SHORT;

const ERROR_UNABLE_TO_PARSE = 'ERROR: Unable to parse';
const ERROR_UNABLE_TO_FORMAT = 'ERROR: Unable to format date';
const ERROR_ARGS_STRING_ARRAY = 'ERROR: Date must be string YYYY-mm-dd HH:ii:ss or array(y,m,d,h,i,s)';
const ERROR_CREATE_INTL_DATE_FMT = 'ERROR: Unable to create international date formatter';

protected $dateFormatter;
```

1.  之后，我们可以定义一个方法`getDateFormatter()`，它返回一个`IntlDateFormatter`实例。`$type`的值与之前定义的`DATE_TYPE_*`常量之一相匹配：

```php
public function getDateFormatter($type)
{
  switch ($type) {
    case self::DATE_TYPE_SHORT :
      $formatter = new IntlDateFormatter($this->getLocaleCode(),
        IntlDateFormatter::SHORT, IntlDateFormatter::SHORT);
      break;
    case self::DATE_TYPE_MEDIUM :
      $formatter = new IntlDateFormatter($this->getLocaleCode(), IntlDateFormatter::MEDIUM, IntlDateFormatter::MEDIUM);
      break;
    case self::DATE_TYPE_LONG :
      $formatter = new IntlDateFormatter($this->getLocaleCode(), IntlDateFormatter::LONG, IntlDateFormatter::LONG);
      break;
    case self::DATE_TYPE_FULL :
      $formatter = new IntlDateFormatter($this->getLocaleCode(), IntlDateFormatter::FULL, IntlDateFormatter::FULL);
      break;
    default :
      throw new InvalidArgumentException(self::ERROR_CREATE_INTL_DATE_FMT);
  }
  $this->dateFormatter = $formatter;
  return $this->dateFormatter;
}
```

1.  接下来，我们定义一个方法，生成一个区域设置格式的日期。定义传入的`$date`的格式有点棘手。它不能是特定于区域设置的，否则我们将需要根据区域设置规则解析它，结果难以预测。更好的策略是接受一个代表年、月、日等值的整数数组。作为备用方案，我们将接受一个字符串，但只能是这种格式：`YYYY-mm-dd HH:ii:ss`。时区是可选的，可以单独设置。首先我们初始化变量：

```php
public function formatDate($date, $type, $timeZone = NULL)
{
  $result   = NULL;
  $year     = date('Y');
  $month    = date('m');
  $day      = date('d');
  $hour     = 0;
  $minutes  = 0;
  $seconds  = 0;
```

1.  之后，我们生成代表年、月、日等值的值的分解：

```php
if (is_string($date)) {
  list($dateParts, $timeParts) = explode(' ', $date);
  list($year,$month,$day) = explode('-',$dateParts);
  list($hour,$minutes,$seconds) = explode(':',$timeParts);
} elseif (is_array($date)) {
  list($year,$month,$day,$hour,$minutes,$seconds) = $date;
} else {
  throw new InvalidArgumentException(self::ERROR_ARGS_STRING_ARRAY);
}
```

1.  接下来，我们创建一个`IntlCalendar`实例，它将作为运行`format()`时的参数。我们使用离散的整数值设置日期：

```php
$intlDate = IntlCalendar::createInstance($timeZone, $this->getLocaleCode());
$intlDate->set($year,$month,$day,$hour,$minutes,$seconds);
```

1.  最后，我们获得日期格式化程序实例，并生成结果：

```php
  $formatter = $this->getDateFormatter($type);
  if ($timeZone) {
    $formatter->setTimeZone($timeZone);
  }
  $result = $formatter->format($intlDate);
  return $result ?? self::ERROR_UNABLE_TO_FORMAT;
}
```

1.  `parseDate()`方法实际上比格式化更简单。唯一的复杂之处在于如果未指定类型要做什么（这可能是最常见的情况）。我们需要做的就是循环遍历所有可能的类型（只有四种），直到产生结果为止：

```php
public function parseDate($string, $type = NULL)
{
 if ($type) {
  $result = $this->getDateFormatter($type)->parse($string);
 } else {
  $tryThese = [self::DATE_TYPE_FULL,
    self::DATE_TYPE_LONG,
    self::DATE_TYPE_MEDIUM,
    self::DATE_TYPE_SHORT];
  foreach ($tryThese as $type) {
  $result = $this->getDateFormatter($type)->parse($string);
    if ($result) {
      break;
    }
  }
 }
 return ($result) ? $result : self::ERROR_UNABLE_TO_PARSE;
}
```

## 它是如何工作的...

对之前讨论过的`Application\I18n\Locale`进行更改。然后，您可以创建一个测试文件`chap_08_formatting_date.php`，设置自动加载，并创建`Locale`类的两个实例，一个用于美国，另一个用于法国：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\I18n\Locale;

$localeFr = new Locale('fr-FR');
$localeUs = new Locale('en_US');
$date     = '2016-02-29 17:23:58';
?>
```

接下来，通过合适的样式，运行`formatDate()`和`parseDate()`的测试：

```php
echo $localeFr->formatDate($date, Locale::DATE_TYPE_FULL);
echo $localeUs->formatDate($date, Locale::DATE_TYPE_MEDIUM);
$localeUs->parseDate($localeFr->formatDate($date, Locale::DATE_TYPE_MEDIUM));
// etc.
```

这里显示了输出的一个示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_06.jpg)

## 另请参阅

+   ISO 8601 为日期和时间的所有方面提供了精确的定义。还有一个 RFC 讨论了 ISO 8601 对互联网的影响。有关参考，请参阅[`tools.ietf.org/html/rfc3339`](https://tools.ietf.org/html/rfc3339)。有关各国日期格式的概述，请参阅[`en.wikipedia.org/wiki/Date_format_by_country`](https://en.wikipedia.org/wiki/Date_format_by_country)。

# 创建 HTML 国际日历生成器

创建一个显示日历的程序是你在中学时最有可能做的事情。一个嵌套的`for()`循环，内部循环生成一个七天的列表，通常就足够了。甚至每个月有多少天这个问题也很容易通过一个简单的数组解决。当你需要弄清楚，在任何给定的年份，1 月 1 日是星期几时，情况就会变得棘手起来。还有，如果你想用特定语言和格式表示月份和星期几，符合特定区域设置的话，会怎么样？正如你可能已经猜到的那样，我们将使用之前讨论过的`Application\I18n\Locale`类构建一个解决方案。

## 操作步骤...

1.  首先，我们需要创建一个通用类，用于保存单日的信息。最初，它只会保存一个整数值`$dayOfMonth`。稍后，在下一个示例中，我们将扩展它以包括事件。由于这个类的主要目的是产生`$dayOfMonth`，我们将把这个值纳入它的构造函数，并定义`__invoke()`来返回这个值：

```php
namespace Application\I18n;

class Day
{
  public $dayOfMonth;
  public function __construct($dayOfMonth)
  {
    $this->dayOfMonth = $dayOfMonth;
  }
  public function __invoke()
  {
    return $this->dayOfMonth ?? '';
  }
}
```

1.  创建一个新的类，它将保存适当的日历生成方法。它将接受一个`Application\I18n\Locale`的实例，并定义一些类常量和属性。格式代码，如`EEEEE`和`MMMM`，是从 ICU 日期格式中提取的：

```php
namespace Application\I18n;

use IntlCalendar;

class Calendar
{

  const DAY_1 = 'EEEEE';  // T
  const DAY_2 = 'EEEEEE'; // Tu
  const DAY_3 = 'EEE';   // Tue
  const DAY_FULL = 'EEEE'; // Tuesday
  const MONTH_1 = 'MMMMM'; // M
  const MONTH_3 = 'MMM';  // Mar
  const MONTH_FULL = 'MMMM';  // March
  const DEFAULT_ACROSS = 3;
  const HEIGHT_FULL = '150px';
  const HEIGHT_SMALL = '60px';

  protected $locale;
  protected $dateFormatter;
  protected $yearArray;
  protected $height;

  public function __construct(Locale $locale)
  {
    $this->locale = $locale;
  }

     // other methods are discussed in the following bullets

}
```

1.  然后我们定义一个方法，从我们的`locale`类中返回一个`IntlDateFormatter`实例。这将存储在一个类属性中，因为它将经常被使用：

```php
protected function getDateFormatter()
{
 if (!$this->dateFormatter) {
  $this->dateFormatter = $this->locale->getDateFormatter(Locale::DATE_TYPE_FULL);
 }
 return $this->dateFormatter;
}
```

1.  接下来，我们定义一个核心方法`buildMonthArray()`，它创建一个多维数组，其中外部键是一年中的周数，内部数组是表示一周的七个元素的天。我们接受年份、月份和可选的时区作为参数。请注意，在变量初始化的一部分中，我们从月份中减去 1。这是因为`IntlCalendar::set()`方法期望月份的基于 0 的值，其中 0 代表一月，1 代表二月，依此类推：

```php
public function buildMonthArray($year, $month, $timeZone = NULL)
{
$month -= 1; 
//IntlCalendar months are 0 based; Jan==0, Feb==1 and so on
  $day = 1;
  $first = TRUE;
  $value = 0;
  $monthArray = array();
```

1.  然后，我们创建一个`IntlCalendar`实例，并使用它来确定这个月有多少天：

```php
$cal = IntlCalendar::createInstance($timeZone, $this->locale->getLocaleCode());
$cal->set($year, $month, $day);
$maxDaysInMonth = $cal->getActualMaximum(IntlCalendar::FIELD_DAY_OF_MONTH);
```

1.  之后，我们使用我们的`IntlDateFormatter`实例来确定这个月的第一天是星期几。之后，我们将模式设置为`w`，随后将给出周数：

```php
$formatter = $this->getDateFormatter();
$formatter->setPattern('e');
$firstDayIsWhatDow = $formatter->format($cal);
```

1.  现在我们准备通过嵌套循环遍历该月的所有天。外部的`while()`循环确保我们不会超过月份的末尾。内部循环表示一周中的天。您会注意到我们利用`IntlCalendar::get()`，它允许我们从各种预定义字段中检索值。如果一年中的周数超过 52，我们还会将周数值调整为 0：

```php
while ($day <= $maxDaysInMonth) {
  for ($dow = 1; $dow <= 7; $dow++) {
    $cal->set($year, $month, $day);
    $weekOfYear = $cal->get(IntlCalendar::FIELD_WEEK_OF_YEAR);
    if ($weekOfYear > 52) $weekOfYear = 0;
```

1.  然后，我们检查`$first`是否仍然设置为`TRUE`。如果是，我们开始向数组添加日期。否则，数组值设置为`NULL`。然后，我们关闭所有打开的语句并返回数组。请注意，我们还需要确保内部循环不会超过月份的天数，因此在外部`else`子句中有额外的`if()`语句。

### 注意

请注意，我们不仅存储月份的值，还使用新定义的`Application\I18n\Day`类。

```php
      if ($first) {
        if ($dow == $firstDayIsWhatDow) {
          $first = FALSE;
          $value = $day++;
        } else {
          $value = NULL;
        }
      } else {
        if ($day <= $maxDaysInMonth) {
          $value = $day++;
        } else {
          $value = NULL;
        }
      }
      $monthArray[$weekOfYear][$dow] = new Day($value);
    }
  }
  return $monthArray;
}
```

### 完善国际化输出

1.  首先，一系列小方法，从提取基于类型的国际格式化日期开始。类型决定我们是否提供星期几的全名、缩写，或者只是一个字母，都适合该区域设置：

```php
protected function getDay($type, $cal)
{
  $formatter = $this->getDateFormatter();
  $formatter->setPattern($type);
  return $formatter->format($cal);
}
```

1.  接下来，我们需要一个方法来返回一个星期几的 HTML 行，调用新定义的`getDay()`方法。如前所述，类型决定了日期的外观：

```php
protected function getWeekHeaderRow($type, $cal, $year, $month, $week)
{
  $output = '<tr>';
  $width  = (int) (100/7);
  foreach ($week as $day) {
    $cal->set($year, $month, $day());
    $output .= '<th style="vertical-align:top;" width="' . $width . '%">' . $this->getDay($type, $cal) . '</th>';
  }
  $output .= '</tr>' . PHP_EOL;
  return $output;
}
```

1.  之后，我们定义一个非常简单的方法来返回一行星期日期。请注意，我们利用`Day::__invoke()`使用：`$day()`：

```php
protected function getWeekDaysRow($week)
{
  $output = '<tr style="height:' . $this->height . ';">';
  $width  = (int) (100/7);
  foreach ($week as $day) {
    $output .= '<td style="vertical-align:top;" width="' . $width . '%">' . $day() .  '</td>';
  }
  $output .= '</tr>' . PHP_EOL;
  return $output;
}
```

1.  最后，一个将较小方法组合在一起生成单个月份日历的方法。首先我们构建月份数组，但只有在`$yearArray`尚不可用时才这样做：

```php
public function calendarForMonth($year, 
    $month, 
    $timeZone = NULL, 
    $dayType = self::DAY_3, 
    $monthType = self::MONTH_FULL, 
    $monthArray = NULL)
{
  $first = 0;
  if (!$monthArray) 
    $monthArray = $this->yearArray[$year][$month]
    ?? $this->buildMonthArray($year, $month, $timeZone);
```

1.  月份需要减去`1`，因为`IntlCalendar`的月份是基于 0 的：1 月= 0，2 月= 1，依此类推。然后，我们使用时区（如果有的话）和区域设置构建一个`IntlCalendar`实例。接下来，我们创建一个`IntlDateFormatter`实例，根据区域设置检索月份名称和其他信息：

```php
  $month--;
  $cal = IntlCalendar::createInstance($timeZone, $this->locale->getLocaleCode());
  $cal->set($year, $month, 1);
  $formatter = $this->getDateFormatter();
  $formatter->setPattern($monthType);
```

1.  然后，我们循环遍历月份数组，并调用刚才提到的较小方法来构建最终的输出：

```php
  $this->height = ($dayType == self::DAY_FULL) 
     ? self::HEIGHT_FULL : self::HEIGHT_SMALL;
  $html = '<h1>' . $formatter->format($cal) . '</h1>';
  $header = '';
  $body   = '';
  foreach ($monthArray as $weekNum => $week) {
    if ($first++ == 1) {
      $header .= $this->getWeekHeaderRow($dayType, $cal, $year, $month, $week);
    }
    $body .= $this->getWeekDaysRow($dayType, $week);
  }
  $html .= '<table>' . $header . $body . '</table>' . PHP_EOL;
  return $html;
}
```

1.  为了生成整年的日历，只需循环遍历 1 到 12 月。为了方便外部访问，我们首先定义一个构建年份数组的方法：

```php
public function buildYearArray($year, $timeZone = NULL)
{
  $this->yearArray = array();
  for ($month = 1; $month <= 12; $month++) {
    $this->yearArray[$year][$month] = $this->buildMonthArray($year, $month, $timeZone);
  }
  return $this->yearArray;
}

public function getYearArray()
{
  return $this->yearArray;
}
```

1.  要为一年生成日历，我们定义一个方法`calendarForYear()`。如果年份数组尚未构建，我们调用`buildYearArray()`。我们考虑要显示多少个月份的日历，然后调用`calendarForMonth()`：

```php
public function calendarForYear($year, 
  $timeZone = NULL, 
  $dayType = self::DAY_1, 
  $monthType = self::MONTH_3, 
  $across = self::DEFAULT_ACROSS)
{
  if (!$this->yearArray) $this->buildYearArray($year, $timeZone);
  $yMax = (int) (12 / $across);
  $width = (int) (100 / $across);
  $output = '<table>' . PHP_EOL;
  $month = 1;
  for ($y = 1; $y <= $yMax; $y++) {
    $output .= '<tr>';
    for ($x = 1; $x <= $across; $x++) {
      $output .= '<td style="vertical-align:top;" width="' . $width . '%">' . $this->calendarForMonth($year, $month, $timeZone, $dayType, $monthType, $this->yearArray[$year][$month++]) . '</td>';
    }
    $output .= '</tr>' . PHP_EOL;
  }
  $output .= '</table>';
  return $output;
}
```

## 它是如何工作的...

首先，确保按照前面的示例构建`Application\I18n\Locale`类。之后，在`Application\I18n`文件夹中创建一个名为`Calendar.php`的新文件，其中包含本示例中描述的所有方法。

接下来，定义一个调用程序`chap_08_html_calendar.php`，设置自动加载并创建`Locale`和`Calendar`实例。还要确保定义年份和月份：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\I18n\Locale;
use Application\I18n\Calendar;

$localeFr = new Locale('fr-FR');
$localeUs = new Locale('en_US');
$localeTh = new Locale('th_TH');
$calendarFr = new Calendar($localeFr);
$calendarUs = new Calendar($localeUs);
$calendarTh = new Calendar($localeTh);
$year = 2016;
$month = 1;
?>
```

然后，您可以开发适当的视图逻辑来显示不同的日历。例如，您可以包括参数来显示完整的月份和日期名称：

```php
<!DOCTYPE html>
<html>
  <head>
  <title>PHP 7 Cookbook</title>
  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <link rel="stylesheet" type="text/css" href="php7cookbook_html_table.css">
  </head>
  <body>
    <h3>Year: <?= $year ?></h3>
    <?= $calendarFr->calendarForMonth($year, $month, NULL, Calendar::DAY_FULL); ?>
    <?= $calendarUs->calendarForMonth($year, $month, NULL, Calendar::DAY_FULL); ?>
    <?= $calendarTh->calendarForMonth($year, $month, NULL, Calendar::DAY_FULL); ?>
  </body>
</html>
```

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_07.jpg)

通过进行一些修改，您还可以显示整年的日历：

```php
$localeTh = new Locale('th_TH');
$localeEs = new Locale('es_ES');
$calendarTh = new Calendar($localeTh);
$calendarEs = new Calendar($localeEs);
$year = 2016;
echo $calendarTh->calendarForYear($year);
echo $calendarEs->calendarForYear($year);
```

这是浏览器输出，显示了一个完整的西班牙语年历：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_08.jpg)

## 另请参阅

+   有关`IntlDateFormatter::setPattern()`使用的代码的更多信息，请参阅本文：[`userguide.icu-project.org/formatparse/datetime`](http://userguide.icu-project.org/formatparse/datetime)

# 构建一个重复事件生成器

与生成日历相关的一个非常普遍的需求是安排事件。事件可以是*一次性*事件，发生在一天，或者在周末。然而，更需要跟踪*重复*事件。我们需要考虑开始日期、重复间隔（每天、每周、每月）以及发生次数或特定的结束日期。

## 如何做...

1.  在任何其他事情之前，创建一个表示事件的类将是一个绝妙的主意。最终，您可能会将数据存储在数据库中的这样一个类中。然而，在本示例中，我们将简单地定义类，并将数据库方面留给您的想象力。您会注意到我们将使用`DateTime`扩展中包含的许多类，这些类非常适合事件生成：

```php
namespace Application\I18n;

use DateTime;
use DatePeriod;
use DateInterval;
use InvalidArgumentException;

class Event
{
  // code
}
```

1.  接下来，我们定义一系列有用的类常量和属性。您会注意到，我们将大多数属性定义为`public`，以节省所需的 getter 和 setter 的数量。间隔被定义为`sprintf()`格式字符串；`%d`将被替换为一个值：

```php
const INTERVAL_DAY = 'P%dD';
const INTERVAL_WEEK = 'P%dW';
const INTERVAL_MONTH = 'P%dM';
const FLAG_FIRST = 'FIRST';    // 1st of the month
const ERROR_INVALID_END  = 'Need to supply either # occurrences or an end date';
const ERROR_INVALID_DATE = 'String i.e. YYYY-mm-dd or DateTime instance only';
const ERROR_INVALID_INTERVAL = 'Interval must take the form "P\d+(D | W | M)"';

public $id;
public $flag;
public $value;
public $title;
public $locale;
public $interval;
public $description;
public $occurrences;
public $nextDate;
protected $endDate;
protected $startDate;
```

1.  接下来，我们将注意力转向构造函数。我们需要收集和设置与事件相关的所有信息。变量名不言自明。

### 注意

`$value`并不是那么清晰。这个参数最终将被替换为间隔格式字符串中的值。因此，例如，如果用户选择`$interval`为`INTERVAL_DAY`，并且`$value`为`2`，则生成的间隔字符串将是`P2D`，这意味着每隔一天（或每隔 2 天）。

```php
public function __construct($title, 
    $description,
    $startDate,
    $interval,
    $value,
    $occurrences = NULL,
    $endDate = NULL,
    $flag = NULL)
{
```

1.  然后我们初始化变量。请注意，ID 是伪随机生成的，但最终可能成为数据库`events`表中的主键。在这里，我们使用`md5()`不是出于安全目的，而是为了快速生成哈希，以便 ID 具有一致的外观：

```php
$this->id = md5($title . $interval . $value) . sprintf('%04d', rand(0,9999));
$this->flag = $flag;
$this->value = $value;
$this->title = $title;
$this->description = $description;
$this->occurrences = $occurrences;
```

1.  如前所述，间隔参数是一个`sprintf()`模式，用于构造适当的`DateInterval`实例：

```php
try {
  $this->interval = new DateInterval(sprintf($interval, $value));
  } catch (Exception $e) {
  error_log($e->getMessage());
  throw new InvalidArgumentException(self::ERROR_INVALID_INTERVAL);
}
```

1.  要初始化`$startDate`，我们调用`stringOrDate()`。然后，我们尝试通过调用`stringOrDate()`或`calcEndDateFromOccurrences()`来生成`$endDate`的值。如果我们既没有结束日期也没有发生次数，就会抛出异常：

```php
  $this->startDate = $this->stringOrDate($startDate);
  if ($endDate) {
    $this->endDate = $this->stringOrDate($endDate);
  } elseif ($occurrences) {
    $this->endDate = $this->calcEndDateFromOccurrences();
  } else {
  throw new InvalidArgumentException(self::ERROR_INVALID_END);
  }
  $this->nextDate = $this->startDate;
}
```

1.  `stringOrDate()`方法由几行代码组成，用于检查日期变量的数据类型，并返回`DateTime`实例或`NULL`：

```php
protected function stringOrDate($date)
{
  if ($date === NULL) { 
    $newDate = NULL;
  } elseif ($date instanceof DateTime) {
    $newDate = $date;
  } elseif (is_string($date)) {
    $newDate = new DateTime($date);
  } else {
    throw new InvalidArgumentException(self::ERROR_INVALID_END);
  }
  return $newDate;
}
```

1.  如果设置了`$occurrences`，我们将从构造函数中调用`calcEndDateFromOccurrences()`方法，以便我们知道此事件的结束日期。我们利用`DatePeriod`类，它提供了基于开始日期、`DateInterval`和发生次数的迭代：

```php
protected function calcEndDateFromOccurrences()
{
  $endDate = new DateTime('now');
  $period = new DatePeriod(
$this->startDate, $this->interval, $this->occurrences);
  foreach ($period as $date) {
    $endDate = $date;
  }
  return $endDate;
}
```

1.  接下来，我们加入一个`__toString()`魔术方法，它简单地回显事件的标题：

```php
public function __toString()
{
  return $this->title;
}
```

1.  我们需要为我们的`Event`类定义的最后一个方法是`getNextDate()`，在生成日历时使用：

```php
public function  getNextDate(DateTime $today)
{
  if ($today > $this->endDate) {
    return FALSE;
  }
  $next = clone $today;
  $next->add($this->interval);
  return $next;
}
```

1.  接下来，我们将注意力转向上一篇食谱中描述的`Application\I18n\Calendar`类。通过进行一些小的修改，我们准备好将我们新定义的`Event`类与日历联系起来。首先，我们添加一个新属性`$events`，以及一个用于以数组形式添加事件的方法。我们使用`Event::$id`属性来确保事件被合并而不是被覆盖：

```php
protected $events = array();
public function addEvent(Event $event)
{
  $this->events[$event->id] = $event;
}
```

1.  接下来，我们添加一个名为`processEvents()`的方法，该方法在构建年历时将`Event`实例添加到`Day`对象中。首先，我们检查是否有任何事件，以及`Day`对象是否为`NULL`。您可能还记得，月初可能不是星期的第一天，因此需要将`Day`对象的值设置为`NULL`。我们当然不希望将事件添加到一个无效的日期！然后，我们调用`Event::getNextDate()`并查看日期是否匹配。如果匹配，我们将`Event`存储到`Day::$events[]`中，并在`Event`对象上设置下一个日期：

```php
protected function processEvents($dayObj, $cal)
{
  if ($this->events && $dayObj()) {
    $calDateTime = $cal->toDateTime();
    foreach ($this->events as $id => $eventObj) {
      $next = $eventObj->getNextDate($eventObj->nextDate);
      if ($next) {
        if ($calDateTime->format('Y-m-d') == 
            $eventObj->nextDate->format('Y-m-d')) {
          $dayObj->events[$eventObj->id] = $eventObj;
          $eventObj->nextDate = $next;
        }
      }
    }
  }
  return $dayObj;
}
```

### 注意

请注意，我们不直接比较两个对象。这样做的两个原因：首先，一个是`DateTime`实例，另一个是`IntlCalendar`实例。另一个更有说服力的原因是，当获取`DateTime`实例时可能包括小时:分钟:秒，导致两个对象之间的实际值差异。

1.  现在我们需要在`buildMonthArray()`方法中添加对`processEvents()`的调用，使其如下所示：

```php
  while ($day <= $maxDaysInMonth) {
    for ($dow = 1; $dow <= 7; $dow++) {
      // add this to the existing code:
      $dayObj = $this->processEvents(new Day($value), $cal);
      $monthArray[$weekOfYear][$dow] = $dayObj;
    }
  }
```

1.  最后，我们需要修改`getWeekDaysRow()`，添加必要的代码以在框内输出事件信息以及日期：

```php
protected function getWeekDaysRow($type, $week)
{
  $output = '<tr style="height:' . $this->height . ';">';
  $width  = (int) (100/7);
  foreach ($week as $day) {
    $events = '';
    if ($day->events) {
      foreach ($day->events as $single) {
        $events .= '<br>' . $single->title;
        if ($type == self::DAY_FULL) {
          $events .= '<br><i>' . $single->description . '</i>';
        }
      }
    }
    $output .= '<td style="vertical-align:top;" width="' . $width . '%">' 
  . $day() . $events . '</td>';
  }
  $output .= '</tr>' . PHP_EOL;
  return $output;
}
```

## 它是如何工作的...

要将事件与日历关联，首先编写步骤 1 到 10 中描述的`Application\I18n\Event`类。接下来，修改`Application\I18n\Calendar`，如步骤 11 到 14 中所述。然后，您可以创建一个测试脚本`chap_08_recurring_events.php`，设置自动加载并创建`Locale`和`Calendar`实例。为了说明，继续使用'`es_ES`'作为区域设置：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\I18n\ { Locale, Calendar, Event };

try {
  $year = 2016;
  $localeEs = new Locale('es_ES');
  $calendarEs = new Calendar($localeEs);
```

现在我们可以开始定义并向日历添加事件。第一个示例添加了一个持续 3 天并从 2016 年 1 月 8 日开始的事件：

```php
  // add event: 3 days
  $title = 'Conf';
  $description = 'Special 3 day symposium on eco-waste';
  $startDate = '2016-01-08';
  $event = new Event($title, $description, $startDate, 
                     Event::INTERVAL_DAY, 1, 2);
  $calendarEs->addEvent($event);
```

以下是另一个示例，即每月 1 日直到 2017 年 9 月发生的事件：

```php
  $title = 'Pay Rent';
  $description = 'Sent rent check to landlord';
  $startDate = new DateTime('2016-02-01');
  $event = new Event($title, $description, $startDate, 
    Event::INTERVAL_MONTH, 1, '2017-09-01', NULL, Event::FLAG_FIRST);
  $calendarEs->addEvent($event);
```

然后，您可以根据需要添加每周、每两周、每月等样本事件。然后关闭`try...catch`块，并生成适当的显示逻辑：

```php
} catch (Throwable $e) {
  $message = $e->getMessage();
}
?>
<!DOCTYPE html>
<head>
  <title>PHP 7 Cookbook</title>
  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <link rel="stylesheet" type="text/css" href="php7cookbook_html_table.css">
</head>
<body>
<h3>Year: <?= $year ?></h3>
<?= $calendarEs->calendarForYear($year, 'Europe/Berlin', 
    Calendar::DAY_3, Calendar::MONTH_FULL, 2); ?>
<?= $calendarEs->calendarForMonth($year, 1  , 'Europe/Berlin', 
    Calendar::DAY_FULL); ?>
</body>
</html>
```

以下是显示年初几个月的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_09.jpg)

## 另请参阅

+   有关可与`get()`一起使用的`IntlCalendar`字段常量的更多信息，请参阅此页面：[`php.net/manual/en/class.intlcalendar.php#intlcalendar.constants`](http://php.net/manual/en/class.intlcalendar.php#intlcalendar.constants)

# 处理翻译而不使用 gettext

翻译是使您的网站对国际客户群体可访问的重要部分。实现这一目标的一种方法是使用基于本地服务器上安装的**GNU** `gettext`操作系统工具的 PHP `gettext`函数。`gettext`有很好的文档和支持，但使用了传统的方法并具有明显的缺点。因此，在本教程中，我们提出了一种替代翻译方法，您可以构建自己的*适配器*。

需要认识到的一点重要的是，PHP 可用的编程翻译工具主要设计为提供单词或短语的有限翻译，称为**msgid**（**消息 ID**）。翻译的等效物称为**msgstr**（**消息字符串**）。因此，通常只涉及相对不变的项目，如菜单、表单、错误或成功消息等。在本教程中，我们将假设您已将实际网页翻译存储为文本块。

### 注意

如果您需要翻译整个页面的内容，您可以考虑使用*Google 翻译 API*。但这是一个付费服务。或者，您可以使用*Amazon Mechanical Turk*以廉价的方式将翻译外包给具有多语言技能的个人。有关 URL，请参阅本教程末尾的*另请参阅*部分。

## 如何做...

1.  我们将再次使用适配器软件设计模式，这次是为了提供翻译源的替代方案。在这个示例中，我们将演示`.ini`文件、`.csv`文件和数据库的适配器。

1.  首先，我们将定义一个接口，稍后将用于标识翻译适配器。翻译适配器的要求非常简单，我们只需要为给定的消息 ID 返回一个消息字符串：

```php
namespace Application\I18n\Translate\Adapter;
interface TranslateAdapterInterface
{
  public function translate($msgid);
}
```

1.  接下来，我们定义一个与接口匹配的特质。特质将包含实际所需的代码。请注意，如果我们未能找到消息字符串，我们只需返回消息 ID：

```php
namespace Application\I18n\Translate\Adapter;

trait TranslateAdapterTrait
{
  protected $translation;
  public function translate($msgid)
  {
    return $this->translation[$msgid] ?? $msgid;
  }
}
```

1.  现在我们准备定义我们的第一个适配器。在这个示例中，我们将从使用`.ini`文件作为翻译源的适配器开始。您会注意到的第一件事是，我们使用了之前定义的特质。构造方法将在适配器之间有所不同。在这种情况下，我们使用`parse_ini_file()`来生成一个键/值对数组，其中键是消息 ID。请注意，我们使用`$filePattern`参数来替换区域设置，然后可以加载适当的翻译文件：

```php
namespace Application\I18n\Translate\Adapter;

use Exception;
use Application\I18n\Locale;

class Ini implements TranslateAdapterInterface
{
  use TranslateAdapterTrait;
  const ERROR_NOT_FOUND = 'Translation file not found';
  public function __construct(Locale $locale, $filePattern)
  {
    $translateFileName = sprintf($filePattern, $locale->getLocaleCode());
    if (!file_exists($translateFileName)) {
      error_log(self::ERROR_NOT_FOUND . ':' . $translateFileName);
      throw new Exception(self::ERROR_NOT_FOUND);
    } else {
      $this->translation = parse_ini_file($translateFileName);
    }
  }
}
```

1.  下一个适配器，`Application\I18n\Translate\Adapter\Csv`，除了打开翻译文件并使用`fgetcsv()`循环检索消息 ID / 消息字符串键值对外，其他都相同。这里我们只展示构造函数中的区别：

```php
public function __construct(Locale $locale, $filePattern)
{
  $translateFileName = sprintf($filePattern, $locale->getLocaleCode());
  if (!file_exists($translateFileName)) {
    error_log(self::ERROR_NOT_FOUND . ':' . $translateFileName);
    throw new Exception(self::ERROR_NOT_FOUND);
  } else {
    $fileObj = new SplFileObject($translateFileName, 'r');
    while ($row = $fileObj->fgetcsv()) {
      $this->translation[$row[0]] = $row[1];
    }
  }
}
```

### 注意

这两个适配器的一个很大的缺点是，我们需要预加载整个翻译集，如果有大量的翻译，这会对内存造成压力。此外，需要打开和解析翻译文件，这会拖慢性能。

1.  现在我们介绍第三个适配器，它执行数据库查找，避免了其他两个适配器的问题。我们使用一个`PDO`准备语句，它在开始时发送到数据库，只发送一次。然后我们根据需要执行多次，提供消息 ID 作为参数。您还会注意到，我们需要覆盖特质中定义的`translate()`方法。最后，您可能已经注意到我们使用了`PDOStatement::fetchColumn()`，因为我们只需要一个值：

```php
namespace Application\I18n\Translate\Adapter;

use Exception;
use Application\Database\Connection;
use Application\I18n\Locale;

class Database implements TranslateAdapterInterface
{
  use TranslateAdapterTrait;
  protected $connection;
  protected $statement;
  protected $defaultLocaleCode;
  public function __construct(Locale $locale, 
                              Connection $connection, 
                              $tableName)
  {
    $this->defaultLocaleCode = $locale->getLocaleCode();
    $this->connection = $connection;
    $sql = 'SELECT msgstr FROM ' . $tableName 
       . ' WHERE localeCode = ? AND msgid = ?';
    $this->statement = $this->connection->pdo->prepare($sql);
  }
  public function translate($msgid, $localeCode = NULL)
  {
    if (!$localeCode) $localeCode = $this->defaultLocaleCode;
    $this->statement->execute([$localeCode, $msgid]);
    return $this->statement->fetchColumn();
  }
}
```

1.  现在我们准备定义核心的`Translation`类，它与一个（或多个）适配器相关联。我们分配一个类常量来表示默认的区域设置，并为区域设置、适配器和文本文件模式（稍后解释）设置属性：

```php
namespace Application\I18n\Translate;

use Application\I18n\Locale;
use Application\I18n\Translate\Adapter\TranslateAdapterInterface;

class Translation
{
  const DEFAULT_LOCALE_CODE = 'en_GB';
  protected $defaultLocaleCode;
  protected $adapter = array();
  protected $textFilePattern = array();
```

1.  在构造函数中，我们确定区域设置，并将初始适配器设置为此区域设置。通过这种方式，我们能够托管多个适配器：

```php
public function __construct(TranslateAdapterInterface $adapter, 
              $defaultLocaleCode = NULL, 
              $textFilePattern = NULL)
{
  if (!$defaultLocaleCode) {
    $this->defaultLocaleCode = self::DEFAULT_LOCALE_CODE;
  } else {
    $this->defaultLocaleCode = $defaultLocaleCode;
  }
  $this->adapter[$this->defaultLocaleCode] = $adapter;
  $this->textFilePattern[$this->defaultLocaleCode] = $textFilePattern;
}
```

1.  接下来，我们定义一系列的 setter，这给了我们更多的灵活性：

```php
public function setAdapter($localeCode, TranslateAdapterInterface $adapter)
{
  $this->adapter[$localeCode] = $adapter;
}
public function setDefaultLocaleCode($localeCode)
{
  $this->defaultLocaleCode = $localeCode;
}
public function setTextFilePattern($localeCode, $pattern)
{
  $this->textFilePattern[$localeCode] = $pattern;
}
```

1.  然后，我们定义了 PHP 魔术方法`__invoke()`，它让我们可以直接调用翻译实例，返回给定消息 ID 的消息字符串：

```php
public function __invoke($msgid, $locale = NULL)
{
  if ($locale === NULL) $locale = $this->defaultLocaleCode;
  return $this->adapter[$locale]->translate($msgid);
}
```

1.  最后，我们还添加了一个方法，可以从文本文件中返回翻译的文本块。请记住，这可以修改为使用数据库。我们没有在适配器中包含这个功能，因为它的目的完全不同；我们只想根据一个键返回大块代码，这个键可能是翻译文本文件的文件名：

```php
public function text($key, $localeCode = NULL)
{
  if ($localeCode === NULL) $localeCode = $this->defaultLocaleCode;
  $contents = $key;
  if (isset($this->textFilePattern[$localeCode])) {
    $fn = sprintf($this->textFilePattern[$localeCode], $localeCode, $key);
    if (file_exists($fn)) {
      $contents = file_get_contents($fn);
    }
  }
  return $contents;
}
```

## 它是如何工作的...

首先，您需要定义一个目录结构来存放翻译文件。为了说明的目的，您可以创建一个目录，`/path/to/project/files/data/languages`。在这个目录结构下，创建代表不同区域设置的子目录。对于这个示例，您可以使用这些：`de_DE`，`fr_FR`，`en_GB`和`es_ES`，分别代表德语、法语、英语和西班牙语。

接下来，您需要创建不同的翻译文件。例如，这是一个代表西班牙语的`data/languages/es_ES/translation.ini`文件：

```php
Welcome=Bienvenido
About Us=Sobre Nosotros
Contact Us=Contáctenos
Find Us=Encontrarnos
click=clic para más información
```

同样，为了演示 CSV 适配器，创建一个相同的 CSV 文件，`data/languages/es_ES/translation.csv`：

```php
"Welcome","Bienvenido"
"About Us","Sobre Nosotros"
"Contact Us","Contáctenos"
"Find Us","Encontrarnos"
"click","clic para más información"
```

最后，创建一个名为`translation`的数据库表，并用相同的数据填充它。主要区别在于数据库表将具有三个字段：`msgid`，`msgstr`和`locale_code`。

```php
CREATE TABLE `translation` (
  `msgid` varchar(255) NOT NULL,
  `msgstr` varchar(255) NOT NULL,
  `locale_code` char(6) NOT NULL DEFAULT '',
  PRIMARY KEY (`msgid`,`locale_code`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
```

接下来，使用本教程中显示的代码定义先前提到的类：

+   `Application\I18n\Translate\Adapter\TranslateAdapterInterface`

+   `Application\I18n\Translate\Adapter\TranslateAdapterTrait`

+   `Application\I18n\Translate\Adapter\Ini`

+   `Application\I18n\Translate\Adapter\Csv`

+   `Application\I18n\Translate\Adapter\Database`

+   `Application\I18n\Translate\Translation`

现在，您可以创建一个名为`chap_08_translation_database.php`的测试文件，以测试数据库翻译适配器。它应该实现自动加载，使用适当的类，并创建`Locale`和`Connection`实例。请注意，`TEXT_FILE_PATTERN`常量是一个`sprintf()`模式，其中区域代码和文件名被替换：

```php
<?php
define('DB_CONFIG_FILE', '/../config/db.config.php');
define('TEXT_FILE_PATTERN', __DIR__ . '/../data/languages/%s/%s.txt');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\I18n\Locale;
use Application\I18n\Translate\ { Translation, Adapter\Database };
use Application\Database\Connection;

$conn = new Connection(include __DIR__ . DB_CONFIG_FILE);
$locale = new Locale('fr_FR');
```

接下来，创建一个翻译适配器实例，并使用它来创建一个`Translation`实例：

```php
$adapter = new Database($locale, $conn, 'translation');
$translate = new Translation($adapter, $locale->getLocaleCode(), TEXT_FILE_PATTERN);
?>
```

最后，创建使用`$translate`实例的显示逻辑：

```php
<!DOCTYPE html>
<head>
  <title>PHP 7 Cookbook</title>
  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <link rel="stylesheet" type="text/css" href="php7cookbook_html_table.css">
</head>
<body>
<table>
<tr>
  <th><h1 style="color:white;"><?= $translate('Welcome') ?></h1></th>
  <td>
    <div style="float:left;width:50%;vertical-align:middle;">
    <h3 style="font-size:24pt;"><i>Some Company, Inc.</i></h3>
    </div>
    <div style="float:right;width:50%;">
    <img src="jcartier-city.png" width="300px"/>
    </div>
  </td>
</tr>
<tr>
  <th>
    <ul>
      <li><?= $translate('About Us') ?></li>
      <li><?= $translate('Contact Us') ?></li>
      <li><?= $translate('Find Us') ?></li>
    </ul>
  </th>
  <td>
    <p>
    <?= $translate->text('main_page'); ?>
    </p>
    <p>
    <a href="#"><?= $translate('click') ?></a>
    </p>
  </td>
</tr>
</table>
</body>
</html>
```

然后，您可以执行其他类似的测试，替换新的区域设置以获得不同的语言，或者使用另一个适配器来测试不同的数据源。以下是使用`fr_FR`区域设置和数据库翻译适配器的输出示例：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_08_10.jpg)

## 另请参阅

+   有关 Google 翻译 API 的更多信息，请参阅[`cloud.google.com/translate/v2/translating-text-with-rest`](https://cloud.google.com/translate/v2/translating-text-with-rest)。

+   有关 Amazon Mechanical Turk 的更多信息，请参阅[`www.mturk.com/mturk/welcome`](https://www.mturk.com/mturk/welcome)。有关`gettext`的更多信息，请参阅[`www.gnu.org/software/gettext/manual/gettext.html`](http://www.gnu.org/software/gettext/manual/gettext.html)。


# 第九章：开发中间件

在本章中，我们将涵盖以下主题：

+   使用中间件进行身份验证

+   使用中间件实现访问控制

+   使用缓存来提高性能

+   实现路由

+   进行跨框架系统调用

+   使用中间件跨语言

# 介绍

在 IT 行业中经常发生的情况是，术语被创造出来，然后被使用和滥用。术语**中间件**也不例外。可以说，这个术语最早是在 2000 年由**互联网工程任务组**（**IETF**）提出的。最初，这个术语是用于指代在传输层（即 TCP/IP）和应用层之间运行的任何软件。最近，特别是随着**PHP 标准推荐编号 7**（**PSR-7**）的接受，中间件，特别是在 PHP 世界中，已经被应用到了 Web 客户端-服务器环境中。

### 注意

本节中的配方将使用附录中定义的具体类，*定义 PSR-7 类*。

# 使用中间件进行身份验证

中间件的一个非常重要的用途是提供身份验证。大多数基于 Web 的应用程序都需要通过用户名和密码验证访问者的能力。通过将 PSR-7 标准纳入身份验证类，您将使其在各个方面都具有通用性，可以说是足够安全，可以在提供 PSR-7 兼容请求和响应对象的任何框架中使用。

## 操作步骤...

1.  我们首先定义一个 `Application\Acl\AuthenticateInterface` 类。我们使用这个接口来支持适配器软件设计模式，通过允许各种适配器，使我们的 `Authenticate` 类更具通用性，每个适配器都可以从不同的来源（例如，从文件中，使用 OAuth2 等）获取身份验证。请注意使用 PHP 7 定义返回值数据类型的能力：

```php
namespace Application\Acl;
use Psr\Http\Message\ { RequestInterface, ResponseInterface };
interface AuthenticateInterface
{
  public function login(RequestInterface $request) : 
    ResponseInterface;
}
```

### 注意

请注意，通过定义一个需要符合 PSR-7 的请求并生成符合 PSR-7 的响应的方法，我们使得此接口具有普遍适用性。

1.  接下来，我们定义实现接口所需的 `login()` 方法的适配器。我们确保使用适当的类，并定义适合的常量和属性。构造函数使用在第五章中定义的 `Application\Database\Connection`：

```php
namespace Application\Acl;
use PDO;
use Application\Database\Connection;
use Psr\Http\Message\ { RequestInterface, ResponseInterface };
use Application\MiddleWare\ { Response, TextStream };
class DbTable  implements AuthenticateInterface
{
  const ERROR_AUTH = 'ERROR: authentication error';
  protected $conn;
  protected $table;
  public function __construct(Connection $conn, $tableName)
  {
    $this->conn = $conn;
    $this->table = $tableName;
  }
```

1.  核心 `login()` 方法从请求对象中提取用户名和密码。然后我们进行直接的数据库查找。如果匹配成功，我们将用户信息存储在响应主体中，以 JSON 编码：

```php
public function login(RequestInterface $request) : 
  ResponseInterface
{
  $code = 401;
  $info = FALSE;
  $body = new TextStream(self::ERROR_AUTH);
  $params = json_decode($request->getBody()->getContents());
  $response = new Response();
  $username = $params->username ?? FALSE;
  if ($username) {
      $sql = 'SELECT * FROM ' . $this->table 
        . ' WHERE email = ?';
      $stmt = $this->conn->pdo->prepare($sql);
      $stmt->execute([$username]);
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      if ($row) {
          if (password_verify($params->password, 
              $row['password'])) {
                unset($row['password']);
                $body = 
                new TextStream(json_encode($row));
                $response->withBody($body);
                $code = 202;
                $info = $row;
              }
            }
          }
          return $response->withBody($body)->withStatus($code);
        }
      }
```

### 提示

**最佳实践**

永远不要以明文形式存储密码。当您需要进行密码匹配时，请使用 `password_verify()`，这样就不需要再生成密码哈希。

1.  `Authenticate` 类是一个实现 `AuthenticationInterface` 的适配器类的包装器。因此，构造函数接受一个适配器类作为参数，以及一个字符串作为密钥，在其中身份验证信息存储在 `$_SESSION` 中：

```php
namespace Application\Acl;
use Application\MiddleWare\ { Response, TextStream };
use Psr\Http\Message\ { RequestInterface, ResponseInterface };
class Authenticate
{
  const ERROR_AUTH = 'ERROR: invalid token';
  const DEFAULT_KEY = 'auth';
  protected $adapter;
  protected $token;
  public function __construct(
  AuthenticateInterface $adapter, $key)
  {
    $this->key = $key;
    $this->adapter = $adapter;
  }
```

1.  此外，我们提供了一个带有安全令牌的登录表单，可以帮助防止**跨站点请求伪造**（**CSRF**）攻击：

```php
public function getToken()
{
  $this->token = bin2hex(random_bytes(16));
  $_SESSION['token'] = $this->token;
  return $this->token;
}
public function matchToken($token)
{
  $sessToken = $_SESSION['token'] ?? date('Ymd');
  return ($token == $sessToken);
}
public function getLoginForm($action = NULL)
{
  $action = ($action) ? 'action="' . $action . '" ' : '';
  $output = '<form method="post" ' . $action . '>';
  $output .= '<table><tr><th>Username</th><td>';
  $output .= '<input type="text" name="username" /></td>';
  $output .= '</tr><tr><th>Password</th><td>';
  $output .= '<input type="password" name="password" />';
  $output .= '</td></tr><tr><th>&nbsp;</th>';
  $output .= '<td><input type="submit" /></td>';
  $output .= '</tr></table>';
  $output .= '<input type="hidden" name="token" value="';
  $output .= $this->getToken() . '" />';
  $output .= '</form>';
  return $output;
}
```

1.  最后，此类中的 `login()` 方法将检查令牌是否有效。如果无效，则返回 400 响应。否则，调用适配器的 `login()` 方法：

```php
public function login(
RequestInterface $request) : ResponseInterface
{
  $params = json_decode($request->getBody()->getContents());
  $token = $params->token ?? FALSE;
  if (!($token && $this->matchToken($token))) {
      $code = 400;
      $body = new TextStream(self::ERROR_AUTH);
      $response = new Response($code, $body);
  } else {
      $response = $this->adapter->login($request);
  }
  if ($response->getStatusCode() >= 200
      && $response->getStatusCode() < 300) {
      $_SESSION[$this->key] = 
        json_decode($response->getBody()->getContents());
  } else {
      $_SESSION[$this->key] = NULL;
  }
  return $response;
}

}
```

## 工作原理...

首先，请确保遵循附录中定义的配方。接下来，继续定义本配方中介绍的类，总结如下表所示：

| 类 | 在这些步骤中讨论 |
| --- | --- |
| `Application\Acl\AuthenticateInterface` | 1 |
| `Application\Acl\DbTable` | 2 - 3 |
| `Application\Acl\Authenticate` | 4 - 6 |

然后，您可以定义一个 `chap_09_middleware_authenticate.php` 调用程序，设置自动加载并使用适当的类：

```php
<?php
session_start();
define('DB_CONFIG_FILE', __DIR__ . '/../config/db.config.php');
define('DB_TABLE', 'customer_09');
define('SESSION_KEY', 'auth');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');

use Application\Database\Connection;
use Application\Acl\ { DbTable, Authenticate };
use Application\MiddleWare\ { ServerRequest, Request, Constants, TextStream };
```

现在您可以设置身份验证适配器和核心类了：

```php
$conn   = new Connection(include DB_CONFIG_FILE);
$dbAuth = new DbTable($conn, DB_TABLE);
$auth   = new Authenticate($dbAuth, SESSION_KEY);
```

确保初始化传入请求，并设置要发送到身份验证类的请求：

```php
$incoming = new ServerRequest();
$incoming->initialize();
$outbound = new Request();
```

检查传入的类方法是否为`POST`。如果是，将请求传递给身份验证类：

```php
if ($incoming->getMethod() == Constants::METHOD_POST) {
  $body = new TextStream(json_encode(
  $incoming->getParsedBody()));
  $response = $auth->login($outbound->withBody($body));
}
$action = $incoming->getServerParams()['PHP_SELF'];
?>
```

显示逻辑如下：

```php
<?= $auth->getLoginForm($action) ?>
```

这是一个无效身份验证尝试的输出。请注意右侧的`401`状态代码。在这个示例中，您可以添加对响应对象的`var_dump()`：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_05.jpg)

这是一个成功的身份验证：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_06.jpg)

## 另请参阅

有关如何避免 CSRF 和其他攻击的指导，请参阅第十二章 *提高 Web 安全性*。

# 使用中间件实现访问控制

顾名思义，中间件位于一系列函数或方法调用的中间。因此，中间件非常适合“门卫”的任务。您可以使用一个中间件类轻松实现**访问控制列表**（**ACL**）机制，该类读取 ACL 并允许或拒绝对序列中下一个函数或方法调用的访问。

## 如何做...

1.  这个过程中可能最困难的部分是确定 ACL 中要包括哪些因素。为了说明，假设我们的用户都被分配了一个`level`和一个`status`。在这个示例中，level 的定义如下：

```php
  'levels' => [0, 'BEG', 'INT', 'ADV']
```

1.  状态可能表示他们在会员注册过程中的进展。例如，状态为`0`可能表示他们已启动会员注册过程，但尚未确认。状态为`1`可能表示他们的电子邮件地址已确认，但他们尚未支付月费，依此类推。

1.  接下来，我们需要定义我们计划控制的资源。在这种情况下，我们将假设有必要控制对站点上一系列网页的访问。因此，我们需要定义一个这样的资源数组。在 ACL 中，我们可以引用键：

```php
'pages'  => [0 => 'sorry', 'logout' => 'logout', 'login'  => 'auth',
             1 => 'page1', 2 => 'page2', 3 => 'page3',
             4 => 'page4', 5 => 'page5', 6 => 'page6',
             7 => 'page7', 8 => 'page8', 9 => 'page9']
```

1.  最后，最重要的配置部分是根据`level`和`status`对页面进行分配。配置数组中使用的通用模板可能如下所示：

```php
status => ['inherits' => <key>, 'pages' => [level => [pages allowed], etc.]]
```

1.  现在我们可以定义`Acl`类了。与以前一样，我们使用了一些类，并定义了适用于访问控制的常量和属性：

```php
namespace Application\Acl;

use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Application\MiddleWare\ { Constants, Response, TextStream };

class Acl
{
  const DEFAULT_STATUS = '';
  const DEFAULT_LEVEL  = 0;
  const DEFAULT_PAGE   = 0;
  const ERROR_ACL = 'ERROR: authorization error';
  const ERROR_APP = 'ERROR: requested page not listed';
  const ERROR_DEF = 
    'ERROR: must assign keys "levels", "pages" and "allowed"';
  protected $default;
  protected $levels;
  protected $pages;
  protected $allowed; 
```

1.  在`__construct()`方法中，我们将分配数组分解为`$pages`（要控制的资源）、`$levels`和`$allowed`（实际分配）。如果数组不包括这三个子组件中的一个，就会抛出异常：

```php
public function __construct(array $assignments)
{
  $this->default = $assignments['default'] 
    ?? self::DEFAULT_PAGE;
  $this->pages   = $assignments['pages'] ?? FALSE;
  $this->levels  = $assignments['levels'] ?? FALSE;
  $this->allowed = $assignments['allowed'] ?? FALSE;
  if (!($this->pages && $this->levels && $this->allowed)) {
      throw new InvalidArgumentException(self::ERROR_DEF);
  }
}
```

1.  您可能已经注意到我们允许继承。在`$allowed`中，`inherits`键可以设置为数组中的另一个键。如果是这样，我们需要将其值与当前正在检查的值合并。我们通过反向迭代`$allowed`，每次循环都合并任何继承的值。顺便说一句，这种方法也只隔离适用于特定`status`和`level`的规则：

```php
protected function mergeInherited($status, $level)
{
  $allowed = $this->allowed[$status]['pages'][$level] 
    ?? array();
  for ($x = $status; $x > 0; $x--) {
    $inherits = $this->allowed[$x]['inherits'];
    if ($inherits) {
        $subArray = 
          $this->allowed[$inherits]['pages'][$level] 
          ?? array();
        $allowed = array_merge($allowed, $subArray);
    }
  }
  return $allowed;
}
```

1.  在处理授权时，我们初始化了一些变量，然后从原始请求 URI 中提取了请求的页面。如果页面参数不存在，我们设置了`400`代码：

```php
public function isAuthorized(RequestInterface $request)
{
  $code = 401;    // unauthorized
  $text['page'] = $this->pages[$this->default];
  $text['authorized'] = FALSE;
  $page = $request->getUri()->getQueryParams()['page'] 
    ?? FALSE;
  if ($page === FALSE) {
      $code = 400;    // bad request
```

1.  否则，我们解码请求体内容，并获取`status`和`level`。然后我们可以调用`mergeInherited()`，它返回一个对此`status`和`level`可访问的页面数组：

```php
} else {
    $params = json_decode(
      $request->getBody()->getContents());
    $status = $params->status ?? self::DEFAULT_LEVEL;
    $level  = $params->level  ?? '*';
    $allowed = $this->mergeInherited($status, $level);
```

1.  如果请求的页面在`$allowed`数组中，我们将状态代码设置为`200`，并返回一个授权设置，以及与请求的页面代码对应的网页：

```php
if (in_array($page, $allowed)) {
    $code = 200;    // OK
    $text['authorized'] = TRUE;
    $text['page'] = $this->pages[$page];
} else {
    $code = 401;            }
}
```

1.  然后我们返回响应，以 JSON 编码，完成：

```php
$body = new TextStream(json_encode($text));
return (new Response())->withStatus($code)
->withBody($body);
}

}
```

## 工作原理...

之后，您需要定义`Application\Acl\Acl`，这在本示例中进行了讨论。现在转到`/path/to/source/for/this/chapter`文件夹并创建两个目录：`public`和`pages`。在`pages`中，创建一系列 PHP 文件，例如`page1.php`，`page2.php`等。以下是其中一个页面的示例：

```php
<?php // page 1 ?>
<h1>Page 1</h1>
<hr>
<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. etc.</p>
```

您还可以定义一个`menu.php`页面，该页面可以包含在输出中：

```php
<?php // menu ?>
<a href="?page=1">Page 1</a>
<a href="?page=2">Page 2</a>
<a href="?page=3">Page 3</a>
// etc.
```

`logout.php`页面应销毁会话：

```php
<?php
  $_SESSION['info'] = FALSE;
  session_destroy();
?>
<a href="/">BACK</a>
```

`auth.php`页面将显示登录屏幕（如前一示例中所述）：

```php
<?= $auth->getLoginForm($action) ?>
```

然后，您可以创建一个配置文件，根据级别和状态允许访问网页。为了举例说明，将其命名为`chap_09_middleware_acl_config.php`并返回一个类似于以下内容的数组：

```php
<?php
$min = [0, 'logout'];
return [
  'default' => 0,     // default page
  'levels' => [0, 'BEG', 'INT', 'ADV'],
  'pages'  => [0 => 'sorry', 
  'logout' => 'logout', 
  'login' => 'auth',
               1 => 'page1', 2 => 'page2', 3 => 'page3',
               4 => 'page4', 5 => 'page5', 6 => 'page6',
               7 => 'page7', 8 => 'page8', 9 => 'page9'],
  'allowed' => [
               0 => ['inherits' => FALSE,
                     'pages' => [ '*' => $min, 'BEG' => $min,
                     'INT' => $min,'ADV' => $min]],
               1 => ['inherits' => FALSE,
                     'pages' => ['*' => ['logout'],
                    'BEG' => [1, 'logout'],
                    'INT' => [1,2, 'logout'],
                    'ADV' => [1,2,3, 'logout']]],
               2 => ['inherits' => 1,
                     'pages' => ['BEG' => [4],
                     'INT' => [4,5],
                     'ADV' => [4,5,6]]],
               3 => ['inherits' => 2,
                     'pages' => ['BEG' => [7],
                     'INT' => [7,8],
                     'ADV' => [7,8,9]]]
    ]
];
```

最后，在`public`文件夹中，定义`index.php`，该文件设置自动加载，并最终调用`Authenticate`和`Acl`类。与其他示例一样，定义配置文件，设置自动加载，并使用某些类。还要记得启动会话：

```php
<?php
session_start();
session_regenerate_id();
define('DB_CONFIG_FILE', __DIR__ . '/../../config/db.config.php');
define('DB_TABLE', 'customer_09');
define('PAGE_DIR', __DIR__ . '/../pages');
define('SESSION_KEY', 'auth');
require __DIR__ . '/../../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/../..');

use Application\Database\Connection;
use Application\Acl\ { Authenticate, Acl };
use Application\MiddleWare\ { ServerRequest, Request, Constants, TextStream };
```

### 提示

**最佳实践**

保护会话是最佳实践。帮助保护会话的一种简单方法是使用`session_regenerate_id()`，它使现有的 PHP 会话标识无效并生成一个新的标识。因此，如果攻击者通过非法手段获得会话标识符，任何给定会话标识符有效的时间窗口将被最小化。

现在您可以拉取 ACL 配置，并为`Authenticate`和`Acl`创建实例：

```php
$config = require __DIR__ . '/../chap_09_middleware_acl_config.php';
$acl    = new Acl($config);
$conn   = new Connection(include DB_CONFIG_FILE);
$dbAuth = new DbTable($conn, DB_TABLE);
$auth   = new Authenticate($dbAuth, SESSION_KEY);
```

接下来，定义传入和传出请求实例：

```php
$incoming = new ServerRequest();
$incoming->initialize();
$outbound = new Request();
```

如果传入的请求方法是`post`，则调用`login()`方法处理身份验证：

```php
if (strtolower($incoming->getMethod()) == Constants::METHOD_POST) {
    $body = new TextStream(json_encode(
    $incoming->getParsedBody()));
    $response = $auth->login($outbound->withBody($body));
}
```

如果为身份验证定义的会话密钥已填充，则表示用户已成功验证。如果没有，我们将编写一个名为**later**的匿名函数，其中包含身份验证登录页面：

```php
$info = $_SESSION[SESSION_KEY] ?? FALSE;
if (!$info) {
    $execute = function () use ($auth) {
      include PAGE_DIR . '/auth.php';
    };
```

否则，您可以继续进行 ACL 检查。您首先需要从原始查询中找到用户想要访问的网页，但是：

```php
} else {
    $query = $incoming->getServerParams()['QUERY_STRING'] ?? '';
```

然后，您可以重新编程`$outbound`请求以包含此信息：

```php
$outbound->withBody(new TextStream(json_encode($info)));
$outbound->getUri()->withQuery($query);
```

接下来，您将能够检查授权，提供传出请求作为参数：

```php
$response = $acl->isAuthorized($outbound);
```

然后，您可以检查`authorized`参数的返回响应，并编写匿名函数以包含返回的`page`参数（如果 OK），以及否则包含`sorry`页面：

```php
$params   = json_decode($response->getBody()->getContents());
$isAllowed = $params->authorized ?? FALSE;
if ($isAllowed) {
    $execute = function () use ($response, $params) {
      include PAGE_DIR .'/' . $params->page . '.php';
      echo '<pre>', var_dump($response), '</pre>';
      echo '<pre>', var_dump($_SESSION[SESSION_KEY]);
      echo '</pre>';
    };
} else {
    $execute = function () use ($response) {
      include PAGE_DIR .'/sorry.php';
      echo '<pre>', var_dump($response), '</pre>';
      echo '<pre>', var_dump($_SESSION[SESSION_KEY]);
      echo '</pre>';
    };
}
}
```

现在，您只需要设置表单操作并在 HTML 中包装匿名函数：

```php
$action = $incoming->getServerParams()['PHP_SELF'];
?>
<!DOCTYPE html>
<head>
  <title>PHP 7 Cookbook</title>
  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
</head>
<body>
  <?php $execute(); ?>
</body>
</html>
```

要测试它，您可以使用内置的 PHP Web 服务器，但是您需要使用`-t`标志指示文档根目录为`public`：

```php
**cd /path/to/source/for/this/chapter**
**php -S localhost:8080 -t public**

```

从浏览器中，您可以访问`http://localhost:8080/` URL。

如果您尝试访问任何页面，您将被重定向回登录页面。根据配置，具有状态=`1`和级别=`BEG`的用户只能访问页面`1`并注销。如果以此用户身份登录，尝试访问页面 2，则输出如下：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_07.jpg)

## 另请参阅

一旦用户登录，此示例依赖于`$_SESSION`作为用户身份验证的唯一手段。有关如何保护 PHP 会话的良好示例，请参见第十二章*提高 Web 安全性*，特别是名为*保护 PHP 会话*的示例。

# 使用缓存提高性能

缓存软件设计模式是存储需要很长时间才能生成的结果的地方。这可以采用漫长的视图脚本或复杂的数据库查询的形式。当然，存储目的地需要具有高性能，如果您希望提高网站访问者的用户体验。由于不同的安装将具有不同的潜在存储目标，因此缓存机制也适用于适配器模式。潜在存储目标的示例包括内存、数据库和文件系统。

## 如何做...

1.  与本章中的其他一些配方一样，由于有共享的常量，我们定义了一个独立的`Application\Cache\Constants`类：

```php
<?php
namespace Application\Cache;

class Constants
{
  const DEFAULT_GROUP  = 'default';
  const DEFAULT_PREFIX = 'CACHE_';
  const DEFAULT_SUFFIX = '.cache';
  const ERROR_GET      = 'ERROR: unable to retrieve from cache';
  // not all constants are shown to conserve space
}
```

1.  由于我们遵循适配器设计模式，接下来我们定义一个接口：

```php
namespace Application\Cache;
interface  CacheAdapterInterface
{
  public function hasKey($key);
  public function getFromCache($key, $group);
  public function saveToCache($key, $data, $group);
  public function removeByKey($key);
  public function removeByGroup($group);
}
```

1.  现在我们准备定义我们的第一个缓存适配器，在这个示例中，我们使用 MySQL 数据库。我们需要定义将保存列名和准备语句的属性：

```php
namespace Application\Cache;
use PDO;
use Application\Database\Connection;
class Database implements CacheAdapterInterface
{
  protected $sql;
  protected $connection;
  protected $table;
  protected $dataColumnName;
  protected $keyColumnName;
  protected $groupColumnName;
  protected $statementHasKey       = NULL;
  protected $statementGetFromCache = NULL;
  protected $statementSaveToCache  = NULL;
  protected $statementRemoveByKey  = NULL;
  protected $statementRemoveByGroup= NULL;
```

1.  构造函数允许我们提供键列名以及`Application\Database\Connection`实例和用于缓存的表的名称：

```php
public function __construct(Connection $connection,
  $table,
  $idColumnName,
  $keyColumnName,
  $dataColumnName,
  $groupColumnName = Constants::DEFAULT_GROUP)
  {
    $this->connection  = $connection;
    $this->setTable($table);
    $this->setIdColumnName($idColumnName);
    $this->setDataColumnName($dataColumnName);
    $this->setKeyColumnName($keyColumnName);
    $this->setGroupColumnName($groupColumnName);
  }
```

1.  接下来的几个方法准备语句，并在访问数据库时调用。我们没有展示所有的方法，但呈现足够的内容来给你一个想法：

```php
public function prepareHasKey()
{
  $sql = 'SELECT `' . $this->idColumnName . '` '
  . 'FROM `'   . $this->table . '` '
  . 'WHERE `'  . $this->keyColumnName . '` = :key ';
  $this->sql[__METHOD__] = $sql;
  $this->statementHasKey = 
  $this->connection->pdo->prepare($sql);
}
public function prepareGetFromCache()
{
  $sql = 'SELECT `' . $this->dataColumnName . '` '
  . 'FROM `'   . $this->table . '` '
  . 'WHERE `'  . $this->keyColumnName . '` = :key '
  . 'AND `'    . $this->groupColumnName . '` = :group';
  $this->sql[__METHOD__] = $sql;
  $this->statementGetFromCache = 
  $this->connection->pdo->prepare($sql);
}
```

1.  现在我们定义一个确定给定键的数据是否存在的方法：

```php
public function hasKey($key)
{
  $result = 0;
  try {
      if (!$this->statementHasKey) $this->prepareHasKey();
          $this->statementHasKey->execute(['key' => $key]);
  } catch (Throwable $e) {
      error_log(__METHOD__ . ':' . $e->getMessage());
      throw new Exception(Constants::ERROR_REMOVE_KEY);
  }
  return (int) $this->statementHasKey
  ->fetch(PDO::FETCH_ASSOC)[$this->idColumnName];
}
```

1.  核心方法是从缓存中读取和写入的方法。这是从缓存中检索的方法。我们只需要执行准备好的语句，执行`SELECT`，带有`WHERE`子句，其中包括键和组：

```php
public function getFromCache(
$key, $group = Constants::DEFAULT_GROUP)
{
  try {
      if (!$this->statementGetFromCache) 
          $this->prepareGetFromCache();
          $this->statementGetFromCache->execute(
            ['key' => $key, 'group' => $group]);
          while ($row = $this->statementGetFromCache
            ->fetch(PDO::FETCH_ASSOC)) {
            if ($row && count($row)) {
                yield unserialize($row[$this->dataColumnName]);
            }
          }
  } catch (Throwable $e) {
      error_log(__METHOD__ . ':' . $e->getMessage());
      throw new Exception(Constants::ERROR_GET);
  }
}
```

1.  写入缓存时，我们首先确定是否存在该缓存键的条目。如果是，我们执行`UPDATE`；否则，我们执行`INSERT`：

```php
public function saveToCache($key, $data, $group = Constants::DEFAULT_GROUP)
{
  $id = $this->hasKey($key);
  $result = 0;
  try {
      if ($id) {
          if (!$this->statementUpdateCache) 
              $this->prepareUpdateCache();
              $result = $this->statementUpdateCache
              ->execute(['key' => $key, 
              'data' => serialize($data), 
              'group' => $group, 
              'id' => $id]);
          } else {
              if (!$this->statementSaveToCache) 
              $this->prepareSaveToCache();
              $result = $this->statementSaveToCache
              ->execute(['key' => $key, 
              'data' => serialize($data), 
              'group' => $group]);
          }
      } catch (Throwable $e) {
          error_log(__METHOD__ . ':' . $e->getMessage());
          throw new Exception(Constants::ERROR_SAVE);
      }
      return $result;
   }
```

1.  然后我们定义了两种方法，通过键或组来删除缓存。通过组删除提供了一个方便的机制，如果有大量需要删除的项目：

```php
public function removeByKey($key)
{
  $result = 0;
  try {
      if (!$this->statementRemoveByKey) 
      $this->prepareRemoveByKey();
      $result = $this->statementRemoveByKey->execute(
        ['key' => $key]);
  } catch (Throwable $e) {
      error_log(__METHOD__ . ':' . $e->getMessage());
      throw new Exception(Constants::ERROR_REMOVE_KEY);
  }
  return $result;
}

public function removeByGroup($group)
{
  $result = 0;
  try {
      if (!$this->statementRemoveByGroup) 
          $this->prepareRemoveByGroup();
          $result = $this->statementRemoveByGroup->execute(
            ['group' => $group]);
      } catch (Throwable $e) {
          error_log(__METHOD__ . ':' . $e->getMessage());
          throw new Exception(Constants::ERROR_REMOVE_GROUP);
      }
      return $result;
  }
```

1.  最后，我们为每个属性定义获取器和设置器。这里没有展示所有的内容以节省空间：

```php
public function setTable($name)
{
  $this->table = $name;
}
public function getTable()
{
  return $this->table;
}
// etc.
}
```

1.  文件系统缓存适配器定义了与之前定义的相同的方法。请注意使用`md5()`，不是为了安全，而是作为一种快速从键生成文本字符串的方法：

```php
namespace Application\Cache;
use RecursiveIteratorIterator;
use RecursiveDirectoryIterator;
class File implements CacheAdapterInterface
{
  protected $dir;
  protected $prefix;
  protected $suffix;
  public function __construct(
    $dir, $prefix = NULL, $suffix = NULL)
  {
    if (!file_exists($dir)) {
        error_log(__METHOD__ . ':' . Constants::ERROR_DIR_NOT);
        throw new Exception(Constants::ERROR_DIR_NOT);
    }
    $this->dir = $dir;
    $this->prefix = $prefix ?? Constants::DEFAULT_PREFIX;
    $this->suffix = $suffix ?? Constants::DEFAULT_SUFFIX;
  }

  public function hasKey($key)
  {
    $action = function ($name, $md5Key, &$item) {
      if (strpos($name, $md5Key) !== FALSE) {
        $item ++;
      }
    };

    return $this->findKey($key, $action);
  }

  public function getFromCache($key, $group = Constants::DEFAULT_GROUP)
  {
    $fn = $this->dir . '/' . $group . '/' 
    . $this->prefix . md5($key) . $this->suffix;
    if (file_exists($fn)) {
        foreach (file($fn) as $line) { yield $line; }
    } else {
        return array();
    }
  }

  public function saveToCache(
    $key, $data, $group = Constants::DEFAULT_GROUP)
  {
    $baseDir = $this->dir . '/' . $group;
    if (!file_exists($baseDir)) mkdir($baseDir);
    $fn = $baseDir . '/' . $this->prefix . md5($key) 
    . $this->suffix;
    return file_put_contents($fn, json_encode($data));
  }

  protected function findKey($key, callable $action)
  {
    $md5Key = md5($key);
    $iterator = new RecursiveIteratorIterator(
      new RecursiveDirectoryIterator($this->dir),
      RecursiveIteratorIterator::SELF_FIRST);
      $item = 0;
    foreach ($iterator as $name => $obj) {
      $action($name, $md5Key, $item);
    }
    return $item;
  }

  public function removeByKey($key)
  {
    $action = function ($name, $md5Key, &$item) {
      if (strpos($name, $md5Key) !== FALSE) {
        unlink($name);
        $item++;
      }
    };
    return $this->findKey($key, $action);
  }

  public function removeByGroup($group)
  {
    $removed = 0;
    $baseDir = $this->dir . '/' . $group;
    $pattern = $baseDir . '/' . $this->prefix . '*' 
    . $this->suffix;
    foreach (glob($pattern) as $file) {
      unlink($file);
      $removed++;
    }
    return $removed;
  }
}
```

1.  现在我们准备介绍核心缓存机制。在构造函数中，我们接受一个实现了`CacheAdapterInterface`的类作为参数：

```php
namespace Application\Cache;
use Psr\Http\Message\RequestInterface;
use Application\MiddleWare\ { Request, Response, TextStream };
class Core
{
  public function __construct(CacheAdapterInterface $adapter)
  {
    $this->adapter = $adapter;
  }
```

1.  接下来是一系列的包装方法，调用适配器中同名的方法，但接受`Psr\Http\Message\RequestInterface`类作为参数，并返回`Psr\Http\Message\ResponseInterface`作为响应。我们从一个简单的开始：`hasKey()`。注意我们如何从请求参数中提取`key`：

```php
public function hasKey(RequestInterface $request)
{
  $key = $request->getUri()->getQueryParams()['key'] ?? '';
  $result = $this->adapter->hasKey($key);
}
```

1.  要从缓存中检索信息，我们需要从请求对象中提取键和组参数，然后调用适配器中的相同方法。如果没有获得结果，我们设置一个`204`代码，表示请求成功，但没有生成内容。否则，我们设置一个`200`（成功）代码，并遍历结果。然后将所有内容放入响应对象中，并返回：

```php
public function getFromCache(RequestInterface $request)
{
  $text = array();
  $key = $request->getUri()->getQueryParams()['key'] ?? '';
  $group = $request->getUri()->getQueryParams()['group'] 
    ?? Constants::DEFAULT_GROUP;
  $results = $this->adapter->getFromCache($key, $group);
  if (!$results) { 
      $code = 204; 
  } else {
      $code = 200;
      foreach ($results as $line) $text[] = $line;
  }
  if (!$text || count($text) == 0) $code = 204;
  $body = new TextStream(json_encode($text));
  return (new Response())->withStatus($code)
                         ->withBody($body);
}
```

1.  奇怪的是，写入缓存几乎与之前定义的方法相同，只是结果预期要么是一个数字（即受影响的行数），要么是一个布尔结果：

```php
public function saveToCache(RequestInterface $request)
{
  $text = array();
  $key = $request->getUri()->getQueryParams()['key'] ?? '';
  $group = $request->getUri()->getQueryParams()['group'] 
    ?? Constants::DEFAULT_GROUP;
  $data = $request->getBody()->getContents();
  $results = $this->adapter->saveToCache($key, $data, $group);
  if (!$results) { 
      $code = 204;
  } else {
      $code = 200;
      $text[] = $results;
  }
      $body = new TextStream(json_encode($text));
      return (new Response())->withStatus($code)
                             ->withBody($body);
  }
```

1.  删除方法与预期相似：

```php
public function removeByKey(RequestInterface $request)
{
  $text = array();
  $key = $request->getUri()->getQueryParams()['key'] ?? '';
  $results = $this->adapter->removeByKey($key);
  if (!$results) {
      $code = 204;
  } else {
      $code = 200;
      $text[] = $results;
  }
  $body = new TextStream(json_encode($text));
  return (new Response())->withStatus($code)
                         ->withBody($body);
}

public function removeByGroup(RequestInterface $request)
{
  $text = array();
  $group = $request->getUri()->getQueryParams()['group'] 
    ?? Constants::DEFAULT_GROUP;
  $results = $this->adapter->removeByGroup($group);
  if (!$results) {
      $code = 204;
  } else {
      $code = 200;
      $text[] = $results;
  }
  $body = new TextStream(json_encode($text));
  return (new Response())->withStatus($code)
                         ->withBody($body);
  }
} // closing brace for class Core
```

## 它是如何工作的...

为了演示`Acl`类的使用，您需要定义本篇文章中描述的类，总结如下：

| 类 | 在这些步骤中讨论 |
| --- | --- |
| `Application\Cache\Constants` | 1 |
| `Application\Cache\CacheAdapterInterface` | 2 |
| `Application\Cache\Database` | 3 - 10 |
| `Application\Cache\File` | 11 |
| `Application\Cache\Core` | 12 - 16 |

接下来，定义一个测试程序，你可以称之为`chap_09_middleware_cache_db.php`。在这个程序中，像往常一样，定义必要文件的常量，设置自动加载，使用适当的类，哦...并编写一个生成质数的函数（你可能在这一点上重新阅读最后一点。不用担心，我们可以帮你解决这个问题！）：

```php
<?php
define('DB_CONFIG_FILE', __DIR__ . '/../config/db.config.php');
define('DB_TABLE', 'cache');
define('CACHE_DIR', __DIR__ . '/cache');
define('MAX_NUM', 100000);
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\Database\Connection;
use Application\Cache\{ Constants, Core, Database, File };
use Application\MiddleWare\ { Request, TextStream };
```

好吧，需要一个运行时间很长的函数，所以质数生成器，我们来吧！数字 1、2 和 3 被给定为质数。我们使用 PHP 7 的`yield from`语法来生成这前三个。然后，我们直接跳到 5，并继续到请求的最大值：

```php
function generatePrimes($max)
{
  yield from [1,2,3];
  for ($x = 5; $x < $max; $x++)
  {
    if($x & 1) {
        $prime = TRUE;
        for($i = 3; $i < $x; $i++) {
            if(($x % $i) === 0) {
                $prime = FALSE;
                break;
            }
        }
        if ($prime) yield $x;
    }
  }
}
```

然后，您可以设置一个数据库缓存适配器实例，作为核心的参数：

```php
$conn    = new Connection(include DB_CONFIG_FILE);
$dbCache = new Database(
  $conn, DB_TABLE, 'id', 'key', 'data', 'group');
$core    = new Core($dbCache);
```

或者，如果您希望使用文件缓存适配器，这是适当的代码：

```php
$fileCache = new File(CACHE_DIR);
$core    = new Core($fileCache);
```

如果您想要清除缓存，可以这样做：

```php
$uriString = '/?group=' . Constants::DEFAULT_GROUP;
$cacheRequest = new Request($uriString, 'get');
$response = $core->removeByGroup($cacheRequest);
```

您可以使用`time()`和`microtime()`来查看此脚本在有缓存和无缓存的情况下运行的时间：

```php
$start = time() + microtime(TRUE);
echo "\nTime: " . $start;
```

接下来，生成一个缓存请求。状态码`200`表示您能够从缓存中获取素数列表：

```php
$uriString = '/?key=Test1';
$cacheRequest = new Request($uriString, 'get');
$response = $core->getFromCache($cacheRequest);
$status   = $response->getStatusCode();
if ($status == 200) {
    $primes = json_decode($response->getBody()->getContents());
```

否则，您可以假设未从缓存中获取任何内容，这意味着您需要生成素数，并将结果保存到缓存中：

```php
} else {
    $primes = array();
    foreach (generatePrimes(MAX_NUM) as $num) {
        $primes[] = $num;
    }
    $body = new TextStream(json_encode($primes));
    $response = $core->saveToCache(
    $cacheRequest->withBody($body));
}
```

然后，您可以检查停止时间，计算差异，并查看您的新素数列表：

```php
$time = time() + microtime(TRUE);
$diff = $time - $start;
echo "\nTime: $time";
echo "\nDifference: $diff";
var_dump($primes);
```

这是在值存储在缓存之前的预期输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_08.jpg)

现在，您可以再次运行相同的程序，这次是从缓存中检索：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_09.jpg)

考虑到我们的小素数生成器不是世界上效率最高的，而且演示是在笔记本电脑上运行的，时间从 30 多秒降到了毫秒。

## 还有更多...

另一个可能的缓存适配器可以围绕**Alternate PHP Cache** (**APC**)扩展的命令构建。该扩展包括诸如`apc_exists()`、`apc_store()`、`apc_fetch()`和`apc_clear_cache()`之类的函数。这些函数非常适合我们的`hasKey()`、`saveToCache()`、`getFromCache()`和`removeBy*()`函数。

## 另请参阅

您可能考虑对先前描述的缓存适配器类进行轻微更改，遵循 PSR-6，这是一个针对缓存的标准建议。然而，对于这个标准的接受程度并不像 PSR-7 那样高，因此我们决定在这里提出的配方中不完全遵循这个标准。有关 PSR-6 的更多信息，请参阅[`www.php-fig.org/psr/psr-6/`](http://www.php-fig.org/psr/psr-6/)。

# 实施路由

路由是指接受用户友好的 URL、解析 URL 为其组成部分，然后确定应该调度哪个类和方法的过程。这种实现的优势在于，不仅可以使您的 URL**搜索引擎优化**（**SEO**）友好，还可以创建规则，包括正则表达式模式，可以提取参数的值。

## 如何做...

1.  可能最受欢迎的方法是利用支持**URL 重写**的 Web 服务器。这样的一个例子是配置为使用`mod_rewrite`的 Apache Web 服务器。然后，您定义重写规则，允许图形文件请求以及对 CSS 和 JavaScript 的请求保持不变。否则，请求将通过路由方法进行处理。

1.  另一种潜在的方法是简单地让您的 Web 服务器虚拟主机定义指向特定的路由脚本，然后调用路由类，做出路由决策，并适当地重定向。

1.  要考虑的第一段代码是如何定义路由配置。显而易见的答案是构造一个数组，其中每个键都指向一个正则表达式，该正则表达式与 URI 路径匹配，并且有某种形式的操作。以下代码片段显示了这种配置的示例。在这个例子中，我们定义了三个路由：`home`、`page`和默认路由。默认路由应该放在最后，因为它将匹配之前未匹配的任何内容。操作以匿名函数的形式呈现，如果路由匹配发生，则将执行该函数：

```php
$config = [
  'home' => [
    'uri' => '!^/$!',
    'exec' => function ($matches) {
      include PAGE_DIR . '/page0.php'; }
  ],
  'page' => [
    'uri' => '!^/(page)/(\d+)$!',
      'exec' => function ($matches) {
        include PAGE_DIR . '/page' . $matches[2] . '.php'; }
  ],
  Router::DEFAULT_MATCH => [
    'uri' => '!.*!',
    'exec' => function ($matches) {
      include PAGE_DIR . '/sorry.php'; }
  ],
];
```

1.  接下来，我们定义我们的`Router`类。我们首先定义在检查和匹配路由过程中将有用的常量和属性：

```php
namespace Application\Routing;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;
class Router
{
  const DEFAULT_MATCH = 'default';
  const ERROR_NO_DEF  = 'ERROR: must supply a default match';
  protected $request;
  protected $requestUri;
  protected $uriParts;
  protected $docRoot;
  protected $config;
  protected $routeMatch;
```

1.  构造函数接受一个符合`ServerRequestInterface`的类、文档根目录的路径以及前面提到的配置文件。请注意，如果未提供默认配置，则会抛出异常：

```php
public function __construct(ServerRequestInterface $request, $docRoot, $config)
{
  $this->config = $config;
  $this->docRoot = $docRoot;
  $this->request = $request;
  $this->requestUri = 
    $request->getServerParams()['REQUEST_URI'];
  $this->uriParts = explode('/', $this->requestUri);
  if (!isset($config[self::DEFAULT_MATCH])) {
      throw new InvalidArgumentException(
        self::ERROR_NO_DEF);
  }
}
```

1.  接下来，我们有一系列的 getter，允许我们检索原始请求、文档根目录和最终路由匹配：

```php
public function getRequest()
{
  return $this->request;
}
public function getDocRoot()
{
  return $this->docRoot;
}
public function getRouteMatch()
{
  return $this->routeMatch;
}
```

1.  `isFileOrDir()`方法用于确定我们是否试图匹配 CSS、JavaScript 或图形请求（以及其他可能性）：

```php
public function isFileOrDir()
{
  $fn = $this->docRoot . '/' . $this->requestUri;
  $fn = str_replace('//', '/', $fn);
  if (file_exists($fn)) {
      return $fn;
  } else {
      return '';
  }
}
```

1.  最后，我们定义了`match()`，它遍历配置数组，并通过`preg_match()`运行`uri`参数。如果匹配成功，则将配置键和`preg_match()`填充的`$matches`数组存储在`$routeMatch`中，并返回回调。如果没有匹配，则返回默认回调：

```php
public function match()
{
  foreach ($this->config as $key => $route) {
    if (preg_match($route['uri'], 
        $this->requestUri, $matches)) {
        $this->routeMatch['key'] = $key;
        $this->routeMatch['match'] = $matches;
        return $route['exec'];
    }
  }
  return $this->config[self::DEFAULT_MATCH]['exec'];
}
}
```

## 工作原理...

首先，切换到`/path/to/source/for/this/chapter`并创建一个名为`routing`的目录。接下来，定义一个文件`index.php`，设置自动加载并使用正确的类。您可以定义一个常量`PAGE_DIR`，指向上一篇文章中创建的`pages`目录：

```php
<?php
define('DOC_ROOT', __DIR__);
define('PAGE_DIR', DOC_ROOT . '/../pages');

require_once __DIR__ . '/../../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/../..');
use Application\MiddleWare\ServerRequest;
use Application\Routing\Router;
```

接下来，添加在本教程第 3 步中讨论的配置数组。请注意，您可以在模式的末尾添加`(/)?`以考虑可选的尾随斜杠。另外，对于`home`路由，您可以提供两个选项：`/`或`/home`：

```php
$config = [
  'home' => [
    'uri' => '!^(/|/home)$!',
    'exec' => function ($matches) {
      include PAGE_DIR . '/page0.php'; }
  ],
  'page' => [
    'uri' => '!^/(page)/(\d+)(/)?$!',
    'exec' => function ($matches) {
      include PAGE_DIR . '/page' . $matches[2] . '.php'; }
  ],
  Router::DEFAULT_MATCH => [
    'uri' => '!.*!',
    'exec' => function ($matches) {
      include PAGE_DIR . '/sorry.php'; }
  ],
];
```

然后，您可以定义一个路由器实例，将初始化的`ServerRequest`实例作为第一个参数提供：

```php
$router = new Router((new ServerRequest())
  ->initialize(), DOC_ROOT, $config);
$execute = $router->match();
$params  = $router->getRouteMatch()['match'];
```

然后，您需要检查请求是文件还是目录，以及路由匹配是否为`/`：

```php
if ($fn = $router->isFileOrDir()
    && $router->getRequest()->getUri()->getPath() != '/') {
    return FALSE;
} else {
    include DOC_ROOT . '/main.php';
}
```

接下来，定义`main.php`，类似于这样：

```php
<?php // demo using middleware for routing ?>
<!DOCTYPE html>
<head>
  <title>PHP 7 Cookbook</title>
  <meta http-equiv="content-type" 
  content="text/html;charset=utf-8" />
</head>
<body>
    <?php include PAGE_DIR . '/route_menu.php'; ?>
    <?php $execute($params); ?>
</body>
</html>
```

最后，需要一个使用用户友好路由的修订菜单：

```php
<?php // menu for routing ?>
<a href="/home">Home</a>
<a href="/page/1">Page 1</a>
<a href="/page/2">Page 2</a>
<a href="/page/3">Page 3</a>
<!-- etc. -->
```

要使用 Apache 测试配置，请定义一个虚拟主机定义，指向`/path/to/source/for/this/chapter/routing`。此外，定义一个`.htaccess`文件，将任何不是文件、目录或链接的请求重定向到`index.php`。或者，您可以直接使用内置的 PHP Web 服务器。在终端窗口或命令提示符中，键入此命令：

```php
**cd /path/to/source/for/this/chapter/routing**
**php -S localhost:8080**

```

在浏览器中，请求`http://localhost:8080/home`时的输出如下：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_10.jpg)

## 另请参阅

有关使用**NGINX** Web 服务器进行重写的信息，请参阅本文：[`nginx.org/en/docs/http/ngx_http_rewrite_module.html`](http://nginx.org/en/docs/http/ngx_http_rewrite_module.html)。有许多复杂的 PHP 路由库可用，介绍的功能远远超过了这里介绍的简单路由器。这些包括 Altorouter ([`altorouter.com/`](http://altorouter.com/))，TreeRoute ([`github.com/baryshev/TreeRoute`](https://github.com/baryshev/TreeRoute))，FastRoute ([`github.com/nikic/FastRoute`](https://github.com/nikic/FastRoute))和 Aura.Router. ([`github.com/auraphp/Aura.Router`](https://github.com/auraphp/Aura.Router))。此外，大多数框架（例如 Zend Framework 2 或 CodeIgniter）都具有自己的路由功能。

# 进行跨框架系统调用

PSR-7（和中间件）开发的主要原因之一是日益增长的需要在框架之间进行调用。值得注意的是，PSR-7 的主要文档由**PHP Framework Interop** **Group** (**PHP-FIG**)托管。

## 操作步骤...

1.  在中间件跨框架调用中使用的主要机制是创建一个驱动程序，依次执行框架调用，维护一个公共的请求和响应对象。预期请求和响应对象分别代表`Psr\Http\Message\ServerRequestInterface`和`Psr\Http\Message\ResponseInterface`。

1.  为了说明这一点，我们定义了一个中间件会话验证器。常量和属性反映了会话`thumbprint`，这是一个我们用来包含网站访问者 IP 地址、浏览器和语言设置等因素的术语：

```php
namespace Application\MiddleWare\Session;
use InvalidArgumentException;
use Psr\Http\Message\ { 
  ServerRequestInterface, ResponseInterface };
use Application\MiddleWare\ { Constants, Response, TextStream };
class Validator
{
  const KEY_TEXT = 'text';
  const KEY_SESSION = 'thumbprint';
  const KEY_STATUS_CODE = 'code';
  const KEY_STATUS_REASON = 'reason';
  const KEY_STOP_TIME = 'stop_time';
  const ERROR_TIME = 'ERROR: session has exceeded stop time';
  const ERROR_SESSION = 'ERROR: thumbprint does not match';
  const SUCCESS_SESSION = 'SUCCESS: session validates OK';
  protected $sessionKey;
  protected $currentPrint;
  protected $storedPrint;
  protected $currentTime;
  protected $storedTime;
```

1.  构造函数接受`ServerRequestInterface`实例和会话作为参数。如果会话是一个数组（比如`$_SESSION`），我们将其包装在一个类中。我们这样做的原因是，以防我们传递了一个会话对象，比如 Joomla 中使用的`JSession`。然后，我们使用先前提到的因素创建指纹。如果存储的指纹不可用，我们假设这是第一次，并存储当前的指纹以及停止时间（如果设置了此参数）。我们使用`md5()`是因为它是一个快速的哈希，不会外部暴露，因此对这个应用程序很有用：

```php
public function __construct(
  ServerRequestInterface $request, $stopTime = NULL)
{
  $this->currentTime  = time();
  $this->storedTime   = $_SESSION[self::KEY_STOP_TIME] ?? 0;
  $this->currentPrint = 
    md5($request->getServerParams()['REMOTE_ADDR']
      . $request->getServerParams()['HTTP_USER_AGENT']
      . $request->getServerParams()['HTTP_ACCEPT_LANGUAGE']);
        $this->storedPrint  = $_SESSION[self::KEY_SESSION] 
      ?? NULL;
  if (empty($this->storedPrint)) {
      $this->storedPrint = $this->currentPrint;
      $_SESSION[self::KEY_SESSION] = $this->storedPrint;
      if ($stopTime) {
          $this->storedTime = $stopTime;
          $_SESSION[self::KEY_STOP_TIME] = $stopTime;
      }
  }
}
```

1.  并不需要定义`__invoke()`，但这个魔术方法对于独立的中间件类非常方便。按照惯例，我们接受`ServerRequestInterface`和`ResponseInterface`实例作为参数。在这个方法中，我们只是检查当前的指纹是否与存储的指纹匹配。第一次，当然，它们会匹配。但在后续请求中，有可能会捕获到试图劫持会话的攻击者。此外，如果会话时间超过了停止时间（如果设置了），同样会发送`401`代码：

```php
public function __invoke(
  ServerRequestInterface $request, Response $response)
{
  $code = 401;  // unauthorized
  if ($this->currentPrint != $this->storedPrint) {
      $text[self::KEY_TEXT] = self::ERROR_SESSION;
      $text[self::KEY_STATUS_REASON] = 
        Constants::STATUS_CODES[401];
  } elseif ($this->storedTime) {
      if ($this->currentTime > $this->storedTime) {
          $text[self::KEY_TEXT] = self::ERROR_TIME;
          $text[self::KEY_STATUS_REASON] = 
            Constants::STATUS_CODES[401];
      } else {
          $code = 200; // success
      }
  }
  if ($code == 200) {
      $text[self::KEY_TEXT] = self::SUCCESS_SESSION;
      $text[self::KEY_STATUS_REASON] = 
        Constants::STATUS_CODES[200];
  }
  $text[self::KEY_STATUS_CODE] = $code;
  $body = new TextStream(json_encode($text));
  return $response->withStatus($code)->withBody($body);
}
```

1.  现在我们可以使用我们的新中间件类。至少在这一点上，不同框架之间的调用存在的主要问题在这里总结。因此，我们如何实现中间件在很大程度上取决于最后一点：

+   并非所有的 PHP 框架都符合 PSR-7

+   现有的 PSR-7 实现并不完整

+   所有框架都想成为“老大”

1.  作为一个例子，让我们来看看**Zend Expressive**的配置文件，它是一个自称为*PSR7 中间件微框架*。这里有一个名为`middleware-pipeline.global.php`的文件，它位于标准 Expressive 应用程序中的`config/autoload`文件夹中。依赖项键用于标识将在管道中激活的中间件包装类：

```php
<?php
use Zend\Expressive\Container\ApplicationFactory;
use Zend\Expressive\Helper;
return [  
  'dependencies' => [
     'factories' => [
        Helper\ServerUrlMiddleware::class => 
        Helper\ServerUrlMiddlewareFactory::class,
        Helper\UrlHelperMiddleware::class => 
        Helper\UrlHelperMiddlewareFactory::class,
        **// insert your own class here**
     ],
  ],
```

1.  在`middleware_pipline`键下，您可以标识在路由过程发生之前或之后将被执行的类。可选参数包括`path`、`error`和`priority`：

```php
'middleware_pipeline' => [
   'always' => [
      'middleware' => [
         Helper\ServerUrlMiddleware::class,
      ],
      'priority' => 10000,
   ],
   'routing' => [
      'middleware' => [
         ApplicationFactory::ROUTING_MIDDLEWARE,
         Helper\UrlHelperMiddleware::class,
         **// insert reference to middleware here**
         ApplicationFactory::DISPATCH_MIDDLEWARE,
      ],
      'priority' => 1,
   ],
   'error' => [
      'middleware' => [
         // Add error middleware here.
      ],
      'error'    => true,
      'priority' => -10000,
    ],
  ],
];
```

1.  另一种技术是修改现有框架模块的源代码，并向符合 PSR-7 的中间件应用程序发出请求。以下是修改**Joomla!**安装以包含中间件会话验证器的示例。

1.  接下来，将此代码添加到`/path/to/joomla`文件夹中的`index.php`文件的末尾。由于 Joomla!使用 Composer，我们可以利用 Composer 自动加载程序：

```php
session_start();    // to support use of $_SESSION
$loader = include __DIR__ . '/libraries/vendor/autoload.php';
$loader->add('Application', __DIR__ . '/libraries/vendor');
$loader->add('Psr', __DIR__ . '/libraries/vendor');
```

1.  然后，创建我们的中间件会话验证器的实例，并在`$app = JFactory::getApplication('site');`之前进行验证请求：

```php
$session = JFactory::getSession();
$request = 
  (new Application\MiddleWare\ServerRequest())->initialize();
$response = new Application\MiddleWare\Response();
$validator = new Application\Security\Session\Validator(
  $request, $session);
$response = $validator($request, $response);
if ($response->getStatusCode() != 200) {
  // take some action
}
```

## 它是如何工作的...

首先，创建描述步骤 2-5 的`Application\MiddleWare\Session\Validator`测试中间件类。然后，您需要转到[`getcomposer.org/`](https://getcomposer.org/)并按照说明获取 Composer。将其下载到`/path/to/source/for/this/chapter`文件夹中。接下来，构建一个基本的 Zend Expressive 应用程序，如下所示。在提示是否选择最小骨架时，请务必选择`No`：

```php
**cd /path/to/source/for/this/chapter**
**php composer.phar create-project zendframework/zend-expressive-skeleton expressive**

```

这将创建一个`/path/to/source/for/this/chapter/expressive`文件夹。切换到这个目录。修改`public/index.php`如下：

```php
<?php
if (php_sapi_name() === 'cli-server'
    && is_file(__DIR__ . parse_url(
$_SERVER['REQUEST_URI'], PHP_URL_PATH))
) {
    return false;
}
chdir(dirname(__DIR__));
**session_start();**
**$_SESSION['time'] = time();**
**$appDir = realpath(__DIR__ . '/../../..');**
**$loader = require 'vendor/autoload.php';**
**$loader->add('Application', $appDir);**
$container = require 'config/container.php';
$app = $container->get(\Zend\Expressive\Application::class);
$app->run();
```

然后，您需要创建一个调用我们会话验证中间件的包装类。创建一个`SessionValidateAction.php`文件，需要放在`/path/to/source/for/this/chapter/expressive/src/App/Action`文件夹中。为了说明这一点，将停止时间参数设置为一个较短的持续时间。在这种情况下，`time() + 10`给您 10 秒：

```php
namespace App\Action;
use Application\MiddleWare\Session\Validator;
use Zend\Diactoros\ { Request, Response };
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
class SessionValidateAction
{
  public function __invoke(ServerRequestInterface $request, 
  ResponseInterface $response, callable $next = null)
  {
    $inbound   = new Response();
    $validator = new Validator($request, **time()+10**);
    $inbound   = $validator($request, $response);
    if ($inbound->getStatusCode() != 200) {
        session_destroy();
        setcookie('PHPSESSID', 0, time()-300);
        $params = json_decode(
          $inbound->getBody()->getContents(), TRUE);
        echo '<h1>',$params[Validator::KEY_TEXT],'</h1>';
        echo '<pre>',var_dump($inbound),'</pre>';
        exit;
    }
    return $next($request,$response);
  }
}
```

现在，您需要将新类添加到中间件管道中。修改`config/autoload/middleware-pipeline.global.php`如下。修改部分用**粗体**显示：

```php
<?php
use Zend\Expressive\Container\ApplicationFactory;
use Zend\Expressive\Helper;
return [
  'dependencies' => [
 **'invokables' => [**
 **App\Action\SessionValidateAction::class =>** 
 **App\Action\SessionValidateAction::class,**
 **],**
   'factories' => [
      Helper\ServerUrlMiddleware::class => 
      Helper\ServerUrlMiddlewareFactory::class,
      Helper\UrlHelperMiddleware::class => 
      Helper\UrlHelperMiddlewareFactory::class,
    ],
  ],
  'middleware_pipeline' => [
      'always' => [
         'middleware' => [
            Helper\ServerUrlMiddleware::class,
         ],
         'priority' => 10000,
      ],
      'routing' => [
         'middleware' => [
            ApplicationFactory::ROUTING_MIDDLEWARE,
            Helper\UrlHelperMiddleware::class,
            **App\Action\SessionValidateAction::class,**
            ApplicationFactory::DISPATCH_MIDDLEWARE,
         ],
         'priority' => 1,
      ],
    'error' => [
       'middleware' => [
          // Add error middleware here.
       ],
       'error'    => true,
       'priority' => -10000,
    ],
  ],
];
```

您可能还考虑修改主页模板以显示`$_SESSION`的状态。相关文件是`/path/to/source/for/this/chapter/expressive/templates/app/home-page.phtml`。只需添加`var_dump($_SESSION)`即可。

最初，您应该看到类似以下的东西：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_11.jpg)

10 秒后，刷新浏览器。现在您应该看到这个：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_12.jpg)

# 使用中间件跨语言

除非您尝试在不同版本的 PHP 之间进行通信，否则 PSR-7 中间件将几乎没有用处。回想一下这个首字母缩略词的含义：**PHP 标准建议**。因此，如果您需要向另一种语言编写的应用程序发出请求，请将其视为任何其他 Web 服务 HTTP 请求。

## 如何做...

1.  在 PHP 4 的情况下，实际上有机会进行面向对象编程的有限支持。因此，最好的方法是降级前三个食谱中描述的基本 PSR-7 类。没有足够的空间来涵盖所有的变化，但我们提供了`Application\MiddleWare\ServerRequest`的潜在 PHP 4 版本。首先要注意的是没有命名空间！因此，我们使用下划线 _ 来代替命名空间分隔符的类名：

```php
class Application_MiddleWare_ServerRequest
extends Application_MiddleWare_Request
implements Psr_Http_Message_ServerRequestInterface
{
```

1.  在 PHP 4 中，所有属性都使用关键字`var`进行标识：

```php
var $serverParams;
var $cookies;
var $queryParams;
// not all properties are shown
```

1.  `initialize()`方法几乎相同，只是在 PHP 4 中不允许使用`$this->getServerParams()['REQUEST_URI']`这样的语法。因此，我们需要将其拆分为一个单独的变量：

```php
function initialize()
{
  $params = $this->getServerParams();
  $this->getCookieParams();
  $this->getQueryParams();
  $this->getUploadedFiles;
  $this->getRequestMethod();
  $this->getContentType();
  $this->getParsedBody();
  return $this->withRequestTarget($params['REQUEST_URI']);
}
```

1.  所有`$_XXX`超全局变量都出现在 PHP 4 的后续版本中：

```php
function getServerParams()
{
  if (!$this->serverParams) {
      $this->serverParams = $_SERVER;
  }
  return $this->serverParams;
}
// not all getXXX() methods are shown to conserve space
```

1.  空合并运算符是在 PHP 7 中引入的。我们需要使用`isset(XXX) ? XXX : '';`代替：

```php
function getRequestMethod()
{
  $params = $this->getServerParams();
  $method = isset($params['REQUEST_METHOD']) 
    ? $params['REQUEST_METHOD'] : '';
  $this->method = strtolower($method);
  return $this->method;
}
```

1.  JSON 扩展是在 PHP 5 中引入的。因此，我们需要满足于原始输入。我们还可以在`json_encode()`和`json_decode()`的位置使用`serialize()`或`unserialize()`：

```php
function getParsedBody()
{
  if (!$this->parsedBody) {
      if (($this->getContentType() == 
           Constants::CONTENT_TYPE_FORM_ENCODED
           || $this->getContentType() == 
           Constants::CONTENT_TYPE_MULTI_FORM)
           && $this->getRequestMethod() == 
           Constants::METHOD_POST)
      {
          $this->parsedBody = $_POST;
      } elseif ($this->getContentType() == 
                Constants::CONTENT_TYPE_JSON
                || $this->getContentType() == 
                Constants::CONTENT_TYPE_HAL_JSON)
      {
          ini_set("allow_url_fopen", true);
          $this->parsedBody = 
            file_get_contents('php://stdin');
      } elseif (!empty($_REQUEST)) {
          $this->parsedBody = $_REQUEST;
      } else {
          ini_set("allow_url_fopen", true);
          $this->parsedBody = 
            file_get_contents('php://stdin');
      }
  }
  return $this->parsedBody;
}
```

1.  `withXXX()`方法在 PHP 4 中基本相同：

```php
function withParsedBody($data)
{
  $this->parsedBody = $data;
  return $this;
}
```

1.  同样，`withoutXXX()`方法也是一样的：

```php
function withoutAttribute($name)
{
  if (isset($this->attributes[$name])) {
      unset($this->attributes[$name]);
  }
  return $this;
}

}
```

1.  对于使用其他语言的网站，我们可以使用 PSR-7 类来制定请求和响应，但随后需要使用 HTTP 客户端与其他网站进行通信。例如，回想一下本章中讨论的“开发 PSR-7 请求类”食谱中的`Request`演示。以下是*它是如何工作的...*部分的示例：

```php
$request = new Request(
  TARGET_WEBSITE_URL,
  Constants::METHOD_POST,
  new TextStream($contents),
  [Constants::HEADER_CONTENT_TYPE => 
  Constants::CONTENT_TYPE_FORM_ENCODED,
  Constants::HEADER_CONTENT_LENGTH => $body->getSize()]
);

$data = http_build_query(['data' => 
$request->getBody()->getContents()]);

$defaults = array(
  CURLOPT_URL => $request->getUri()->getUriString(),
  CURLOPT_POST => true,
  CURLOPT_POSTFIELDS => $data,
);
$ch = curl_init();
curl_setopt_array($ch, $defaults);
$response = curl_exec($ch);
curl_close($ch);
```
