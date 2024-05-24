# PHP7 编程秘籍（七）

> 原文：[`zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb`](https://zh.annas-archive.org/md5/2ddf943a2c311275def462dcde4895fb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 A. 定义 PSR-7 类

在本附录中，我们将涵盖以下主题：

+   实现 PSR-7 值对象类

+   开发一个 PSR-7 请求类

+   定义一个 PSR-7 响应类

# 介绍

**PHP 标准建议编号 7**（**PSR-7**）定义了许多接口，但没有提供实际的实现。因此，我们需要定义具体的代码实现，以开始创建自定义中间件。

# 实现 PSR-7 值对象类

为了处理 PSR-7 请求和响应，我们首先需要定义一系列值对象。这些是代表在基于 Web 的活动中使用的逻辑对象的类，如 URI、文件上传和流式请求或响应主体。

## 准备工作

PSR-7 接口的源代码可作为`Composer`包使用。使用`Composer`来管理外部软件，包括 PSR-7 接口，被认为是最佳实践。

## 如何做到这一点...

1.  首先，转到以下 URL 以获取 PSR-7 接口定义的最新版本：[`github.com/php-fig/http-message`](https://github.com/php-fig/http-message)。源代码也可用。在撰写本文时，以下定义可用：

| 接口 | 扩展 | 注释 | 方法处理的内容 |
| --- | --- | --- | --- |
| `MessageInterface` |   | 定义 HTTP 消息的公共方法 | 标头、消息主体（即内容）和协议 |
| `RequestInterface` | `MessageInterface` | 代表客户端生成的请求 | URI、HTTP 方法和请求目标 |
| `ServerRequestInterface` | `RequestInterface` | 代表来自客户端的服务器请求 | 服务器和查询参数、cookie、上传的文件和解析的主体 |
| `ResponseInterface` | `MessageInterface` | 代表服务器对客户端的响应 | HTTP 状态码和原因 |
| `StreamInterface` |   | 代表数据流 | 流式行为，如 seek、tell、read、write 等 |
| `UriInterface` |   | 代表 URI | 方案（即 HTTP、HTTPS）、主机、端口、用户名、密码（即 FTP）、查询参数、路径和片段 |
| `UploadedFileInterface` |   | 处理上传的文件 | 文件大小、媒体类型、移动文件和文件名 |

1.  不幸的是，我们需要创建实现这些接口的具体类，以利用 PSR-7。幸运的是，接口类在内部通过一系列注释进行了广泛的文档化。我们将从一个包含有用常量的单独类开始：

### 提示

请注意，我们利用了 PHP 7 中引入的一个新功能，允许我们将常量定义为数组。

```php
namespace Application\MiddleWare;
class Constants
{
  const HEADER_HOST   = 'Host';     // host header
  const HEADER_CONTENT_TYPE = 'Content-Type';
  const HEADER_CONTENT_LENGTH = 'Content-Length';

  const METHOD_GET    = 'get';
  const METHOD_POST   = 'post';
  const METHOD_PUT    = 'put';
  const METHOD_DELETE = 'delete';
  const HTTP_METHODS  = ['get','put','post','delete'];

  const STANDARD_PORTS = [
    'ftp' => 21, 'ssh' => 22, 'http' => 80, 'https' => 443
  ];

  const CONTENT_TYPE_FORM_ENCODED = 
    'application/x-www-form-urlencoded';
  const CONTENT_TYPE_MULTI_FORM   = 'multipart/form-data';
  const CONTENT_TYPE_JSON         = 'application/json';
  const CONTENT_TYPE_HAL_JSON     = 'application/hal+json';

  const DEFAULT_STATUS_CODE    = 200;
  const DEFAULT_BODY_STREAM    = 'php://input';
  const DEFAULT_REQUEST_TARGET = '/';

  const MODE_READ = 'r';
  const MODE_WRITE = 'w';

  // NOTE: not all error constants are shown to conserve space
  const ERROR_BAD = 'ERROR: ';
  const ERROR_UNKNOWN = 'ERROR: unknown';

  // NOTE: not all status codes are shown here!
  const STATUS_CODES = [
    200 => 'OK',
    301 => 'Moved Permanently',
    302 => 'Found',
    401 => 'Unauthorized',
    404 => 'Not Found',
    405 => 'Method Not Allowed',
    418 => 'I_m A Teapot',
    500 => 'Internal Server Error',
  ];
}
```

### 注意

HTTP 状态码的完整列表可以在这里找到：[`tools.ietf.org/html/rfc7231#section-6.1`](https://tools.ietf.org/html/rfc7231#section-6.1)。

1.  接下来，我们将处理代表其他 PSR-7 类使用的值对象的类。首先，这是代表 URI 的类。在构造函数中，我们接受一个 URI 字符串作为参数，并使用`parse_url()`函数将其分解为其组件部分：

```php
namespace Application\MiddleWare;
use InvalidArgumentException;
use Psr\Http\Message\UriInterface;
class Uri implements UriInterface
{
  protected $uriString;
  protected $uriParts = array();

  public function __construct($uriString)
  {
    $this->uriParts = parse_url($uriString);
    if (!$this->uriParts) {
      throw new InvalidArgumentException(
        Constants::ERROR_INVALID_URI);
    }
    $this->uriString = $uriString;
  }
```

### 注意

**URI**代表**统一资源标识符**。这是在发出请求时在浏览器顶部看到的内容。有关 URI 的构成，请参阅[`tools.ietf.org/html/rfc3986`](http://tools.ietf.org/html/rfc3986)。

1.  在构造函数之后，我们定义了访问 URI 组件部分的方法。**方案**代表 PHP 包装器（即 HTTP、FTP 等）：

```php
public function getScheme()
{
  return strtolower($this->uriParts['scheme']) ?? '';
}
```

1.  **权限**代表用户名（如果存在）、主机和可选的端口号：

```php
public function getAuthority()
{
  $val = '';
  if (!empty($this->getUserInfo()))
  $val .= $this->getUserInfo() . '@';
  $val .= $this->uriParts['host'] ?? '';
  if (!empty($this->uriParts['port']))
  $val .= ':' . $this->uriParts['port'];
  return $val;
}
```

1.  **用户信息**代表用户名（如果存在）和可选的密码。使用密码的一个例子是访问 FTP 网站，如`ftp://username:password@website.com:/path`：

```php
public function getUserInfo()
{
  if (empty($this->uriParts['user'])) {
    return '';
  }
  $val = $this->uriParts['user'];
  if (!empty($this->uriParts['pass']))
    $val .= ':' . $this->uriParts['pass'];
  return $val;
}
```

1.  **主机**是 URI 中包含的 DNS 地址：

```php
public function getHost()
{
  if (empty($this->uriParts['host'])) {
    return '';
  }
  return strtolower($this->uriParts['host']);
}
```

1.  **Port**是 HTTP 端口，如果存在的话。您会注意到，如果端口在我们的`STANDARD_PORTS`常量中列出，返回值是`NULL`，根据 PSR-7 的要求：

```php
public function getPort()
{
  if (empty($this->uriParts['port'])) {
      return NULL;
  } else {
      if ($this->getScheme()) {
          if ($this->uriParts['port'] == 
              Constants::STANDARD_PORTS[$this->getScheme()]) {
              return NULL;
          }
      }
      return (int) $this->uriParts['port'];
  }
}
```

1.  **Path**是跟随 DNS 地址的 URI 的一部分。根据 PSR-7，这必须进行编码。我们使用`rawurlencode()` PHP 函数，因为它符合 RFC 3986。然而，我们不能只对整个路径进行编码，因为路径分隔符（即`/`）也会被编码！因此，我们需要首先使用`explode()`将其分解，对部分进行编码，然后重新组装：

```php
public function getPath()
{
  if (empty($this->urlParts['path'])) {
    return '';
  }
  return implode('/', array_map("rawurlencode", explode('/', $this->urlParts['path'])));
}
```

1.  接下来，我们定义一个方法来检索`query`字符串（即来自`$_GET`）。这些也必须进行 URL 编码。首先，我们定义了`getQueryParams()`，它将查询字符串分解为关联数组。您会注意到重置选项，以防我们希望刷新查询参数。然后我们定义了`getQuery()`，它接受数组并生成一个正确的 URL 编码字符串：

```php
public function getQueryParams($reset = FALSE)
{
  if ($this->queryParams && !$reset) {
    return $this->queryParams;
  }
  $this->queryParams = [];
  if (!empty($this->uriParts['query'])) {
    foreach (explode('&', $this->uriParts['query']) as $keyPair) {
      list($param,$value) = explode('=',$keyPair);
      $this->queryParams[$param] = $value;
    }
  }
  return $this->queryParams;
}

public function getQuery()
{
  if (!$this->getQueryParams()) {
    return '';
  }
  $output = '';
  foreach ($this->getQueryParams() as $key => $value) {
    $output .= rawurlencode($key) . '=' 
    . rawurlencode($value) . '&';
  }
  return substr($output, 0, -1);
}
```

1.  之后，我们提供了一个方法来返回`fragment`（即 URI 中的`#`）以及其后的任何部分：

```php
public function getFragment()
{
  if (empty($this->urlParts['fragment'])) {
    return '';
  }
  return rawurlencode($this->urlParts['fragment']);
}
```

1.  接下来，我们定义了一系列`withXXX()`方法，与上面描述的`getXXX()`方法相匹配。这些方法旨在添加、替换或删除与请求类相关的属性（scheme、authority、user info 等）。此外，这些方法返回当前实例，允许我们在一系列连续调用中使用这些方法（通常称为**流畅接口**）。我们从`withScheme()`开始：

### 注意

根据 PSR-7，空参数表示删除该属性。您还会注意到，我们不允许与我们的`Constants::STANDARD_PORTS`数组中定义的不匹配的方案。

```php
public function withScheme($scheme)
{
  if (empty($scheme) && $this->getScheme()) {
      unset($this->uriParts['scheme']);
  } else {
      if (isset(STANDARD_PORTS[strtolower($scheme)])) {
          $this->uriParts['scheme'] = $scheme;
      } else {
          throw new InvalidArgumentException(Constants::ERROR_BAD . __METHOD__);
      }
  }
  return $this;
}
```

1.  然后，我们对覆盖、添加或替换用户信息、主机、端口、路径、查询和片段的方法应用类似的逻辑。请注意，`withQuery()`方法会重置查询参数数组。`withHost()`、`withPort()`、`withPath()`和`withFragment()`使用相同的逻辑，但未显示以节省空间：

```php
public function withUserInfo($user, $password = null)
{
  if (empty($user) && $this->getUserInfo()) {
      unset($this->uriParts['user']);
  } else {
      $this->urlParts['user'] = $user;
      if ($password) {
          $this->urlParts['pass'] = $password;
      }
  }
  return $this;
}
// Not shown: withHost(),withPort(),withPath(),withFragment()

public function withQuery($query)
{
  if (empty($query) && $this->getQuery()) {
      unset($this->uriParts['query']);
  } else {
      $this->uriParts['query'] = $query;
  }
  // reset query params array
  $this->getQueryParams(TRUE);
  return $this;
}
```

1.  最后，我们用`__toString()`包装`Application\MiddleWare\Uri`类，当对象在字符串上下文中使用时，返回一个由`$uriParts`组装而成的正确 URI。我们还定义了一个方便的方法`getUriString()`，它只是调用`__toString()`：

```php
public function __toString()
{
    $uri = ($this->getScheme())
      ? $this->getScheme() . '://' : '';
```

1.  如果`authority` URI 部分存在，我们会添加它。`authority`包括用户信息、主机和端口。否则，我们只是附加`host`和`port`：

```php
if ($this->getAuthority()) {
    $uri .= $this->getAuthority();
} else {
    $uri .= ($this->getHost()) ? $this->getHost() : '';
    $uri .= ($this->getPort())
      ? ':' . $this->getPort() : '';
}
```

1.  在添加`path`之前，我们首先检查第一个字符是否为`/`。如果不是，我们需要添加这个分隔符。然后，如果存在，我们添加`query`和`fragment`：

```php
$path = $this->getPath();
if ($path) {
    if ($path[0] != '/') {
        $uri .= '/' . $path;
    } else {
        $uri .= $path;
    }
}
$uri .= ($this->getQuery())
  ? '?' . $this->getQuery() : '';
$uri .= ($this->getFragment())
  ? '#' . $this->getFragment() : '';
return $uri;
}

public function getUriString()
{
  return $this->__toString();
}

}
```

### 注意

请注意字符串解引用的使用（即`$path[0]`），这是 PHP 7 的一部分。

1.  接下来，我们将注意力转向表示消息正文的类。由于不知道正文可能有多大，PSR-7 建议将正文视为**流**。流是一种允许以线性方式访问输入和输出源的资源。在 PHP 中，所有文件命令都是在`Streams`子系统之上运行的，因此这是一个自然的选择。PSR-7 通过`Psr\Http\Message\StreamInterface`来规范化这一点，该接口定义了`read()`、`write()`、`seek()`等方法。我们现在介绍`Application\MiddleWare\Stream`，我们可以用它来表示传入或传出请求和/或响应的正文：

```php
namespace Application\MiddleWare;
use SplFileInfo;
use Throwable;
use RuntimeException;
use Psr\Http\Message\StreamInterface;
class Stream implements StreamInterface
{
  protected $stream;
  protected $metadata;
  protected $info;
```

1.  在构造函数中，我们使用简单的`fopen()`命令打开流。然后我们使用`stream_get_meta_data()`获取流的信息。对于其他细节，我们创建一个`SplFileInfo`实例：

```php
public function __construct($input, $mode = self::MODE_READ)
{
  $this->stream = fopen($input, $mode);
  $this->metadata = stream_get_meta_data($this->stream);
  $this->info = new SplFileInfo($input);
}
```

### 注意

我们选择`fopen()`而不是更现代的`SplFileObject`的原因是，后者不允许直接访问内部文件资源对象，因此对于这个应用程序是无用的。

1.  我们包括两个方便的方法，提供对资源的访问，以及对`SplFileInfo`实例的访问：

```php
public function getStream()
{
  return $this->stream;
}

public function getInfo()
{
  return $this->info;
}
```

1.  接下来，我们定义了低级核心流方法：

```php
public function read($length)
{
  if (!fread($this->stream, $length)) {
      throw new RuntimeException(self::ERROR_BAD . __METHOD__);
  }
}
public function write($string)
{
  if (!fwrite($this->stream, $string)) {
      throw new RuntimeException(self::ERROR_BAD . __METHOD__);
  }
}
public function rewind()
{
  if (!rewind($this->stream)) {
      throw new RuntimeException(self::ERROR_BAD . __METHOD__);
  }
}
public function eof()
{
  return eof($this->stream);
}
public function tell()
{
  try {
      return ftell($this->stream);
  } catch (Throwable $e) {
      throw new RuntimeException(self::ERROR_BAD . __METHOD__);
  }
}
public function seek($offset, $whence = SEEK_SET)
{
  try {
      fseek($this->stream, $offset, $whence);
  } catch (Throwable $e) {
      throw new RuntimeException(self::ERROR_BAD . __METHOD__);
  }
}
public function close()
{
  if ($this->stream) {
    fclose($this->stream);
  }
}
public function detach()
{
  return $this->close();
}
```

1.  我们还需要定义告诉我们有关流的信息方法：

```php
public function getMetadata($key = null)
{
  if ($key) {
      return $this->metadata[$key] ?? NULL;
  } else {
      return $this->metadata;
  }
}
public function getSize()
{
  return $this->info->getSize();
}
public function isSeekable()
{
  return boolval($this->metadata['seekable']);
}
public function isWritable()
{
  return $this->stream->isWritable();
}
public function isReadable()
{
  return $this->info->isReadable();
}
```

1.  遵循 PSR-7 指南，然后定义`getContents()`和`__toString()`以便转储流的内容：

```php
public function __toString()
{
  $this->rewind();
  return $this->getContents();
}

public function getContents()
{
  ob_start();
  if (!fpassthru($this->stream)) {
    throw new RuntimeException(self::ERROR_BAD . __METHOD__);
  }
  return ob_get_clean();
}
}
```

1.  先前显示的`Stream`类的一个重要变体是`TextStream`，它专为主体是字符串（即以 JSON 编码的数组）而不是文件的情况而设计。由于我们需要确保传入的`$input`值绝对是字符串数据类型，因此我们在开标签后立即调用 PHP 7 严格类型。我们还标识了一个`$pos`属性（即位置），它将模拟文件指针，但实际上指向字符串中的位置：

```php
<?php
declare(strict_types=1);
namespace Application\MiddleWare;
use Throwable;
use RuntimeException;
use SplFileInfo;
use Psr\Http\Message\StreamInterface;

class TextStream implements StreamInterface
{
  protected $stream;
  protected $pos = 0;
```

1.  大多数方法都非常简单且不言自明。`$stream`属性是输入字符串：

```php
public function __construct(string $input)
{
  $this->stream = $input;
}
public function getStream()
{
  return $this->stream;
}
  public function getInfo()
{
  return NULL;
}
public function getContents()
{
  return $this->stream;
}
public function __toString()
{
  return $this->getContents();
}
public function getSize()
{
  return strlen($this->stream);
}
public function close()
{
  // do nothing: how can you "close" string???
}
public function detach()
{
  return $this->close();  // that is, do nothing!
}
```

1.  为了模拟流式行为，`tell()`，`eof()`，`seek()`等方法与`$pos`一起工作：

```php
public function tell()
{
  return $this->pos;
}
public function eof()
{
  return ($this->pos == strlen($this->stream));
}
public function isSeekable()
{
  return TRUE;
}
public function seek($offset, $whence = NULL)
{
  if ($offset < $this->getSize()) {
      $this->pos = $offset;
  } else {
      throw new RuntimeException(
        Constants::ERROR_BAD . __METHOD__);
  }
}
public function rewind()
{
  $this->pos = 0;
}
public function isWritable()
{
  return TRUE;
}
```

1.  `read()`和`write()`方法与`$pos`和子字符串一起工作：

```php
public function write($string)
{
  $temp = substr($this->stream, 0, $this->pos);
  $this->stream = $temp . $string;
  $this->pos = strlen($this->stream);
}

public function isReadable()
{
  return TRUE;
}
public function read($length)
{
  return substr($this->stream, $this->pos, $length);
}
public function getMetadata($key = null)
{
  return NULL;
}

}
```

1.  最后要介绍的值对象是`Application\MiddleWare\UploadedFile`。与其他类一样，我们首先定义代表文件上传方面的属性：

```php
namespace Application\MiddleWare;
use RuntimeException;
use InvalidArgumentException;
use Psr\Http\Message\UploadedFileInterface;
class UploadedFile implements UploadedFileInterface
{

  protected $field;   // original name of file upload field
  protected $info;    // $_FILES[$field]
  protected $randomize;
  protected $movedName = '';
```

1.  在构造函数中，我们允许定义文件上传表单字段的名称属性，以及`$_FILES`中的对应数组。我们添加最后一个参数来表示是否希望类在确认上传文件后生成新的随机文件名：

```php
public function __construct($field, array $info, $randomize = FALSE)
{
  $this->field = $field;
  $this->info = $info;
  $this->randomize = $randomize;
}
```

1.  接下来，我们为临时或移动的文件创建一个`Stream`类实例：

```php
public function getStream()
{
  if (!$this->stream) {
      if ($this->movedName) {
          $this->stream = new Stream($this->movedName);
      } else {
          $this->stream = new Stream($info['tmp_name']);
      }
  }
  return $this->stream;
}
```

1.  `moveTo()`方法执行实际的文件移动。请注意，我们进行了广泛的安全检查，以帮助防止注入攻击。如果未启用随机化，则使用原始用户提供的文件名：

```php
public function moveTo($targetPath)
{
  if ($this->moved) {
      throw new Exception(Constants::ERROR_MOVE_DONE);
  }
  if (!file_exists($targetPath)) {
      throw new InvalidArgumentException(Constants::ERROR_BAD_DIR);
  }
  $tempFile = $this->info['tmp_name'] ?? FALSE;
  if (!$tempFile || !file_exists($tempFile)) {
      throw new Exception(Constants::ERROR_BAD_FILE);
  }
  if (!is_uploaded_file($tempFile)) {
      throw new Exception(Constants::ERROR_FILE_NOT);
  }
  if ($this->randomize) {
      $final = bin2hex(random_bytes(8)) . '.txt';
  } else {
      $final = $this->info['name'];
  }
  $final = $targetPath . '/' . $final;
  $final = str_replace('//', '/', $final);
  if (!move_uploaded_file($tempFile, $final)) {
      throw new RuntimeException(Constants::ERROR_MOVE_UNABLE);
  }
  $this->movedName = $final;
  return TRUE;
}
```

1.  然后，我们通过`$info`属性提供对`$_FILES`中返回的其他参数的访问。请注意，`getClientFilename()`和`getClientMediaType()`的返回值应被视为不受信任，因为它们来自外部。我们还添加了一个返回移动后的文件名的方法：

```php
public function getMovedName()
{
  return $this->movedName ?? NULL;
}
public function getSize()
{
  return $this->info['size'] ?? NULL;
}
public function getError()
{
  if (!$this->moved) {
      return UPLOAD_ERR_OK;
  }
  return $this->info['error'];
}
public function getClientFilename()
{
  return $this->info['name'] ?? NULL;
}
public function getClientMediaType()
{
  return $this->info['type'] ?? NULL;
}

}
```

## 它是如何工作的...

首先，转到[`github.com/php-fig/http-message/tree/master/src`](https://github.com/php-fig/http-message/tree/master/src)，PSR-7 接口的 GitHub 存储库，并下载它们。在`/path/to/source`中创建一个名为`Psr/Http/Message`的目录，并将文件放在那里。或者，您可以访问[`packagist.org/packages/psr/http-message`](https://packagist.org/packages/psr/http-message)并使用`Composer`安装源代码。（有关如何获取和使用`Composer`的说明，您可以访问[`getcomposer.org/`](https://getcomposer.org/)。）

然后，继续定义先前讨论的类，总结在这个表中：

| 类 | 讨论中的步骤 |
| --- | --- |
| `Application\MiddleWare\Constants` | 2 |
| `Application\MiddleWare\Uri` | 3 to 16 |
| `Application\MiddleWare\Stream` | 17 to 22 |
| `Application\MiddleWare\TextStream` | 23 to 26 |
| `Application\MiddleWare\UploadedFile` | 27 to 31 |

接下来，定义一个调用程序`chap_09_middleware_value_objects_uri.php`，实现自动加载并使用适当的类。请注意，如果您使用`Composer`，除非另有说明，它将创建一个名为`vendor`的文件夹。`Composer`还会添加自己的自动加载程序，您可以在此处自由使用：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\MiddleWare\Uri;
```

然后，您可以创建一个`Uri`实例，并使用`with`方法添加参数。然后，您可以直接将`Uri`实例作为`__toString()`定义的内容输出：

```php
$uri = new Uri();
$uri->withScheme('https')
    ->withHost('localhost')
    ->withPort('8080')
    ->withPath('chap_09_middleware_value_objects_uri.php')
    ->withQuery('param=TEST');

echo $uri;
```

以下是预期结果：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_01.jpg)

接下来，从`/path/to/source/for/this/chapter`创建一个名为`uploads`的目录。继续定义另一个调用程序`chap_09_middleware_value_objects_file_upload.php`，设置自动加载并使用适当的类：

```php
<?php
define('TARGET_DIR', __DIR__ . '/uploads');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\MiddleWare\UploadedFile;
```

在`try...catch`块内，检查是否上传了任何文件。如果是这样，循环遍历`$_FILES`并创建`UploadedFile`实例，其中设置了`tmp_name`。然后可以使用`moveTo()`方法将文件移动到`TARGET_DIR`：

```php
try {
    $message = '';
    $uploadedFiles = array();
    if (isset($_FILES)) {
        foreach ($_FILES as $key => $info) {
          if ($info['tmp_name']) {
              $uploadedFiles[$key] = new UploadedFile($key, $info, TRUE);
              $uploadedFiles[$key]->moveTo(TARGET_DIR);
          }
        }
    }
} catch (Throwable $e) {
    $message =  $e->getMessage();
}
?>
```

在视图逻辑中，显示一个简单的文件上传表单。您还可以使用`phpinfo（）`来显示有关上传内容的信息：

```php
<form name="search" method="post" enctype="<?= Constants::CONTENT_TYPE_MULTI_FORM ?>">
<table class="display" cellspacing="0" width="100%">
    <tr><th>Upload 1</th><td><input type="file" name="upload_1" /></td></tr>
    <tr><th>Upload 2</th><td><input type="file" name="upload_2" /></td></tr>
    <tr><th>Upload 3</th><td><input type="file" name="upload_3" /></td></tr>
    <tr><th>&nbsp;</th><td><input type="submit" /></td></tr>
</table>
</form>
<?= ($message) ? '<h1>' . $message . '</h1>' : ''; ?>
```

接下来，如果有任何上传的文件，您可以显示每个文件的信息。您还可以使用`getStream()`，然后使用`getContents()`来显示每个文件（假设您正在使用短文本文件）：

```php
<?php if ($uploadedFiles) : ?>
<table class="display" cellspacing="0" width="100%">
    <tr>
        <th>Filename</th><th>Size</th>
      <th>Moved Filename</th><th>Text</th>
    </tr>
    <?php foreach ($uploadedFiles as $obj) : ?>
        <?php if ($obj->getMovedName()) : ?>
        <tr>
            <td><?= htmlspecialchars($obj->getClientFilename()) ?></td>
            <td><?= $obj->getSize() ?></td>
            <td><?= $obj->getMovedName() ?></td>
            <td><?= $obj->getStream()->getContents() ?></td>
        </tr>
        <?php endif; ?>
    <?php endforeach; ?>
</table>
<?php endif; ?>
<?php phpinfo(INFO_VARIABLES); ?>
```

以下是输出可能会出现的方式：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_02.jpg)

## 另请参阅

+   有关更多关于 PSR 的信息，请查看[`en.wikipedia.org/wiki/PHP_Standard_Recommendation`](https://en.wikipedia.org/wiki/PHP_Standard_Recommendation)

+   有关 PSR-7 的信息，请参阅官方描述：[`www.php-fig.org/psr/psr-7/`](http://www.php-fig.org/psr/psr-7/)

+   有关 PHP 流的信息，请查看[`php.net/manual/en/book.stream.php`](http://php.net/manual/en/book.stream.php)

# 开发 PSR-7 请求类

PSR-7 中间件的一个关键特征是使用**Request**和**Response**类。应用时，这使得软件的不同块可以一起执行，而不共享它们之间的任何特定知识。在这种情况下，请求类应该包括原始用户请求的所有方面，包括浏览器设置、原始请求的 URL、传递的参数等。

## 如何做...

1.  首先，确保定义类来表示`Uri`、`Stream`和`UploadedFile`值对象，如前一篇中所述。

1.  现在我们准备定义核心的`Application\MiddleWare\Message`类。这个类使用`Stream`和`Uri`，并实现`Psr\Http\Message\MessageInterface`。我们首先为键值对象定义属性，包括表示消息正文（即`StreamInterface`实例）、版本和 HTTP 标头的属性：

```php
namespace Application\MiddleWare;
use Psr\Http\Message\ { 
  MessageInterface, 
  StreamInterface, 
  UriInterface 
};
class Message implements MessageInterface
{
  protected $body;
  protected $version;
  protected $httpHeaders = array();
```

1.  接下来，我们有一个代表`StreamInterface`实例的`getBody()`方法。一个伴随方法`withBody()`返回当前的`Message`实例，并允许我们覆盖`body`的当前值：

```php
public function getBody()
{
  if (!$this->body) {
      $this->body = new Stream(self::DEFAULT_BODY_STREAM);
  }
  return $this->body;
}
public function withBody(StreamInterface $body)
{
  if (!$body->isReadable()) {
      throw new InvalidArgumentException(self::ERROR_BODY_UNREADABLE);
  }
  $this->body = $body;
  return $this;
}
```

1.  PSR-7 建议将标头视为不区分大小写。因此，我们定义了一个`findHeader()`方法（不是直接由`MessageInterface`定义的），它使用`stripos()`来定位标头：

```php
protected function findHeader($name)
{
  $found = FALSE;
  foreach (array_keys($this->getHeaders()) as $header) {
    if (stripos($header, $name) !== FALSE) {
        $found = $header;
        break;
    }
  }
  return $found;
}
```

1.  下一个方法，不是由 PSR-7 定义的，旨在填充`$httpHeaders`属性。假定此属性是一个关联数组，其中键是标头，值是表示标头值的字符串。如果有多个值，则用逗号分隔的附加值附加到字符串中。如果`$httpHeaders`中没有可用的标头，有一个很好的`apache_request_headers()` PHP 函数来自 Apache 扩展，可以生成标头：

```php
protected function getHttpHeaders()
{
  if (!$this->httpHeaders) {
      if (function_exists('apache_request_headers')) {
          $this->httpHeaders = apache_request_headers();
      } else {
          $this->httpHeaders = $this->altApacheReqHeaders();
      }
  }
  return $this->httpHeaders;
}
```

1.  如果`apache_request_headers()`不可用（即，Apache 扩展未启用），我们提供一个替代方案，`altApacheReqHeaders()`：

```php
protected function altApacheReqHeaders()
{
  $headers = array();
  foreach ($_SERVER as $key => $value) {
    if (stripos($key, 'HTTP_') !== FALSE) {
        $headerKey = str_ireplace('HTTP_', '', $key);
        $headers[$this->explodeHeader($headerKey)] = $value;
    } elseif (stripos($key, 'CONTENT_') !== FALSE) {
        $headers[$this->explodeHeader($key)] = $value;
    }
  }
  return $headers;
}
protected function explodeHeader($header)
{
  $headerParts = explode('_', $header);
  $headerKey = ucwords(implode(' ', strtolower($headerParts)));
  return str_replace(' ', '-', $headerKey);
}
```

1.  实现`getHeaders()`（在 PSR-7 中是必需的）现在是通过`getHttpHeaders()`方法产生的`$httpHeaders`属性的一个微不足道的循环：

```php
public function getHeaders()
{
  foreach ($this->getHttpHeaders() as $key => $value) {
    header($key . ': ' . $value);
  }
}
```

1.  同样，我们提供了一系列`with`方法，用于覆盖或替换标头。由于可能有许多标头，我们还有一个方法，用于添加到现有的标头集。`withoutHeader()`方法用于删除标头实例。请注意，在前一步骤中提到的`findHeader()`的一致使用，以允许对标头进行不区分大小写的处理：

```php
public function withHeader($name, $value)
{
  $found = $this->findHeader($name);
  if ($found) {
      $this->httpHeaders[$found] = $value;
  } else {
      $this->httpHeaders[$name] = $value;
  }
  return $this;
}

public function withAddedHeader($name, $value)
{
  $found = $this->findHeader($name);
  if ($found) {
      $this->httpHeaders[$found] .= $value;
  } else {
      $this->httpHeaders[$name] = $value;
  }
  return $this;
}

public function withoutHeader($name)
{
  $found = $this->findHeader($name);
  if ($found) {
      unset($this->httpHeaders[$found]);
  }
  return $this;
}
```

1.  然后，我们提供了一系列有用的与标头相关的方法，以确认标头是否存在，检索单个标头行，并按照 PSR-7 的要求以数组形式检索标头：

```php
public function hasHeader($name)
{
  return boolval($this->findHeader($name));
}

public function getHeaderLine($name)
{
  $found = $this->findHeader($name);
  if ($found) {
      return $this->httpHeaders[$found];
  } else {
      return '';
  }
}

public function getHeader($name)
{
  $line = $this->getHeaderLine($name);
  if ($line) {
      return explode(',', $line);
  } else {
      return array();
  }
}
```

1.  最后，为了完成头处理，我们提供了`getHeadersAsString`，它生成一个由`\r\n`分隔的头字符串，以便直接在 PHP 流上下文中使用：

```php
public function getHeadersAsString()
{
  $output = '';
  $headers = $this->getHeaders();
  if ($headers && is_array($headers)) {
      foreach ($headers as $key => $value) {
        if ($output) {
            $output .= "\r\n" . $key . ': ' . $value;
        } else {
            $output .= $key . ': ' . $value;
        }
      }
  }
  return $output;
}
```

1.  在`Message`类中，我们现在将注意力转向版本处理。根据 PSR-7，协议版本（即 HTTP/1.1）的返回值应该只是数字部分。因此，我们还提供了`onlyVersion()`，它会去掉任何非数字字符，包括句点：

```php
public function getProtocolVersion()
{
  if (!$this->version) {
      $this->version = $this->onlyVersion($_SERVER['SERVER_PROTOCOL']);
  }
  return $this->version;
}

public function withProtocolVersion($version)
{
  $this->version = $this->onlyVersion($version);
  return $this;
}

protected function onlyVersion($version)
{
  if (!empty($version)) {
      return preg_replace('/[⁰-9\.]/', '', $version);
  } else {
      return NULL;
  }
}

}
```

1.  最后，几乎可以说是一个反高潮，我们准备定义我们的`Request`类。然而，需要注意的是，我们需要考虑出站请求和入站请求。也就是说，我们需要一个类来表示客户端将向服务器发出的出站请求，以及服务器从客户端*接收*的请求。因此，我们提供`Application\MiddleWare\Request`（客户端将向服务器发出的请求）和`Application\MiddleWare\ServerRequest`（服务器从客户端接收的请求）。好消息是，我们的大部分工作已经完成：注意我们的`Request`类扩展了`Message`。我们还提供了表示 URI 和 HTTP 方法的属性：

```php
namespace Application\MiddleWare;

use InvalidArgumentException;
use Psr\Http\Message\ { RequestInterface, StreamInterface, UriInterface };

class Request extends Message implements RequestInterface
{
  protected $uri;
  protected $method; // HTTP method
  protected $uriObj; // Psr\Http\Message\UriInterface instance
```

1.  构造函数中的所有属性默认为`NULL`，但我们留下了立即定义适当参数的可能性。我们使用继承的`onlyVersion()`方法来清理版本。我们还定义了`checkMethod()`来确保提供的任何方法都在我们支持的 HTTP 方法列表中，该列表在`Constants`中定义为常量数组：

```php
public function __construct($uri = NULL,
                            $method = NULL,
                            StreamInterface $body = NULL,
                            $headers = NULL,
                            $version = NULL)
{
  $this->uri = $uri;
  $this->body = $body;
  $this->method = $this->checkMethod($method);
  $this->httpHeaders = $headers;
  $this->version = $this->onlyVersion($version);
}
protected function checkMethod($method)
{
  if (!$method === NULL) {
      if (!in_array(strtolower($method), Constants::HTTP_METHODS)) {
          throw new InvalidArgumentException(Constants::ERROR_HTTP_METHOD);
      }
  }
  return $method;
}
```

1.  我们将解释请求目标为最初请求的 URI 的字符串形式。请记住，我们的`Uri`类有方法可以将其解析为其组成部分，因此我们提供了`$uriObj`属性。在`withRequestTarget()`的情况下，注意我们运行了执行前述解析过程的`getUri()`：

```php
public function getRequestTarget()
{
  return $this->uri ?? Constants::DEFAULT_REQUEST_TARGET;
}

public function withRequestTarget($requestTarget)
{
  $this->uri = $requestTarget;
  $this->getUri();
  return $this;
}
```

1.  我们的`get`和`with`方法代表 HTTP 方法，没有什么意外。我们使用在构造函数中使用的`checkMethod()`来确保方法与我们计划支持的方法匹配：

```php
public function getMethod()
{
  return $this->method;
}

public function withMethod($method)
{
  $this->method = $this->checkMethod($method);
  return $this;
}
```

1.  最后，我们为 URI 提供了`get`和`with`方法。如第 14 步中所述，我们保留了`$uri`属性中的原始请求字符串，并在`$uriObj`中保留了新解析的`Uri`实例。注意额外的标志以保留任何现有的`Host`头：

```php
public function getUri()
{
  if (!$this->uriObj) {
      $this->uriObj = new Uri($this->uri);
  }
  return $this->uriObj;
}

public function withUri(UriInterface $uri, $preserveHost = false)
{
  if ($preserveHost) {
    $found = $this->findHeader(Constants::HEADER_HOST);
    if (!$found && $uri->getHost()) {
      $this->httpHeaders[Constants::HEADER_HOST] = $uri->getHost();
    }
  } elseif ($uri->getHost()) {
      $this->httpHeaders[Constants::HEADER_HOST] = $uri->getHost();
  }
  $this->uri = $uri->__toString();
  return $this;
  }
}
```

1.  `ServerRequest`类扩展了`Request`，并提供了额外的功能来检索对服务器处理传入请求感兴趣的信息。我们首先定义将代表从各种 PHP`$_ super-globals`（即`$_SERVER`，`$_POST`等）读取的传入数据的属性：

```php
namespace Application\MiddleWare;
use Psr\Http\Message\ { ServerRequestInterface, UploadedFileInterface } ;

class ServerRequest extends Request implements ServerRequestInterface
{

  protected $serverParams;
  protected $cookies;
  protected $queryParams;
  protected $contentType;
  protected $parsedBody;
  protected $attributes;
  protected $method;
  protected $uploadedFileInfo;
  protected $uploadedFileObjs;
```

1.  然后，我们定义了一系列 getter 来提取超全局信息。为了节省空间，我们没有展示所有内容：

```php
public function getServerParams()
{
  if (!$this->serverParams) {
      $this->serverParams = $_SERVER;
  }
  return $this->serverParams;
}
// getCookieParams() reads $_COOKIE
// getQueryParams() reads $_GET
// getUploadedFileInfo() reads $_FILES

public function getRequestMethod()
{
  $method = $this->getServerParams()['REQUEST_METHOD'] ?? '';
  $this->method = strtolower($method);
  return $this->method;
}

public function getContentType()
{
  if (!$this->contentType) {
      $this->contentType = $this->getServerParams()['CONTENT_TYPE'] ?? '';
      $this->contentType = strtolower($this->contentType);
  }
  return $this->contentType;
}
```

1.  由于上传的文件应该表示为独立的`UploadedFile`对象（在上一个示例中介绍），我们还定义了一个方法，该方法接受`$uploadedFileInfo`并创建`UploadedFile`对象：

```php
public function getUploadedFiles()
{
  if (!$this->uploadedFileObjs) {
      foreach ($this->getUploadedFileInfo() as $field => $value) {
        $this->uploadedFileObjs[$field] = new UploadedFile($field, $value);
      }
  }
  return $this->uploadedFileObjs;
}
```

1.  与先前定义的其他类一样，我们提供了`with`方法，用于添加或覆盖属性并返回新实例：

```php
public function withCookieParams(array $cookies)
{
  array_merge($this->getCookieParams(), $cookies);
  return $this;
}
public function withQueryParams(array $query)
{
  array_merge($this->getQueryParams(), $query);
  return $this;
}
public function withUploadedFiles(array $uploadedFiles)
{
  if (!count($uploadedFiles)) {
      throw new InvalidArgumentException(Constant::ERROR_NO_UPLOADED_FILES);
  }
  foreach ($uploadedFiles as $fileObj) {
    if (!$fileObj instanceof UploadedFileInterface) {
        throw new InvalidArgumentException(Constant::ERROR_INVALID_UPLOADED);
    }
  }
  $this->uploadedFileObjs = $uploadedFiles;
}
```

1.  PSR-7 消息的一个重要方面是，消息体也应以解析的方式可用，也就是说，一种结构化表示，而不仅仅是原始流。因此，我们定义了`getParsedBody()`及其相应的`with`方法。PSR-7 的建议在涉及表单提交时非常具体。请注意一系列检查`Content-Type`头以及方法的`if`语句：

```php
public function getParsedBody()
{
  if (!$this->parsedBody) {
      if (($this->getContentType() == Constants::CONTENT_TYPE_FORM_ENCODED
           || $this->getContentType() == Constants::CONTENT_TYPE_MULTI_FORM)
           && $this->getRequestMethod() == Constants::METHOD_POST)
      {
          $this->parsedBody = $_POST;
      } elseif ($this->getContentType() == Constants::CONTENT_TYPE_JSON
                || $this->getContentType() == Constants::CONTENT_TYPE_HAL_JSON)
      {
          ini_set("allow_url_fopen", true);
          $this->parsedBody = json_decode(file_get_contents('php://input'));
      } elseif (!empty($_REQUEST)) {
          $this->parsedBody = $_REQUEST;
      } else {
          ini_set("allow_url_fopen", true);
          $this->parsedBody = file_get_contents('php://input');
      }
  }
  return $this->parsedBody;
}

public function withParsedBody($data)
{
  $this->parsedBody = $data;
  return $this;
}
```

1.  我们还允许不是在 PSR-7 中精确定义的属性。相反，我们保持开放，以便开发人员可以提供适用于应用程序的任何内容。注意使用`withoutAttributes()`可以随意删除属性：

```php
public function getAttributes()
{
  return $this->attributes;
}
public function getAttribute($name, $default = NULL)
{
  return $this->attributes[$name] ?? $default;
}
public function withAttribute($name, $value)
{
  $this->attributes[$name] = $value;
  return $this;
}
public function withoutAttribute($name)
{
  if (isset($this->attributes[$name])) {
      unset($this->attributes[$name]);
  }
  return $this;
}

}
```

1.  最后，为了从入站请求中加载不同的属性，我们定义了`initialize()`，这不在 PSR-7 中，但非常方便：

```php
public function initialize()
{
  $this->getServerParams();
  $this->getCookieParams();
  $this->getQueryParams();
  $this->getUploadedFiles;
  $this->getRequestMethod();
  $this->getContentType();
  $this->getParsedBody();
  return $this;
}
```

## 工作原理...

首先，确保完成前面的配方，因为`Message`和`Request`类消耗`Uri`、`Stream`和`UploadedFile`值对象。之后，继续定义下表中总结的类：

| 类 | 讨论的步骤 |
| --- | --- |
| `Application\MiddleWare\Message` | 2 到 9 |
| `Application\MiddleWare\Request` | 10 到 14 |
| `Application\MiddleWare\ServerRequest` | 15 到 20 |

之后，您可以定义一个服务器程序`chap_09_middleware_server.php`，设置自动加载并使用适当的类。此脚本将把传入的请求拉入`ServerRequest`实例中，初始化它，然后使用`var_dump()`来显示接收到的信息：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\MiddleWare\ServerRequest;

$request = new ServerRequest();
$request->initialize();
echo '<pre>', var_dump($request), '</pre>';
```

要运行服务器程序，首先切换到`/path/to/source/for/this/chapter`文件夹。然后运行以下命令：

```php
**php -S localhost:8080 chap_09_middleware_server.php'**

```

至于客户端，首先创建一个调用程序`chap_09_middleware_request.php`，设置自动加载，使用适当的类，并定义目标服务器和本地文本文件：

```php
<?php
define('READ_FILE', __DIR__ . '/gettysburg.txt');
define('TEST_SERVER', 'http://localhost:8080');
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\MiddleWare\ { Request, Stream, Constants };
```

接下来，您可以使用文本作为源创建一个`Stream`实例。这将成为一个新请求的主体，在这种情况下，它与表单提交所期望的相同：

```php
$body = new Stream(READ_FILE);
```

然后，您可以直接构建一个`Request`实例，根据需要提供参数：

```php
$request = new Request(
    TEST_SERVER,
    Constants::METHOD_POST,
    $body,
    [Constants::HEADER_CONTENT_TYPE => Constants::CONTENT_TYPE_FORM_ENCODED,Constants::HEADER_CONTENT_LENGTH => $body->getSize()]
);
```

或者，您可以使用流畅的接口语法来产生完全相同的结果：

```php
$uriObj = new Uri(TEST_SERVER);
$request = new Request();
$request->withRequestTarget(TEST_SERVER)
        ->withMethod(Constants::METHOD_POST)
        ->withBody($body)
        ->withHeader(Constants::HEADER_CONTENT_TYPE, Constants::CONTENT_TYPE_FORM_ENCODED)
        ->withAddedHeader(Constants::HEADER_CONTENT_LENGTH, $body->getSize());
```

然后，您可以设置一个 cURL 资源来模拟表单提交，其中数据参数是文本文件的内容。您可以跟着`curl_init()`，`curl_exec()`等，回显结果：

```php
$data = http_build_query(['data' => $request->getBody()->getContents()]);
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

以下是直接输出的样子：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_03.jpg)

## 另请参阅

+   *Matthew Weir O'Phinney*撰写的一个很好的示例用法文章，他是 PSR-7 的编辑（也是 Zend Framework 1、2 和 3 的首席架构师），可以在这里找到：[`mwop.net/blog/2015-01-26-psr-7-by-example.html`](https://mwop.net/blog/2015-01-26-psr-7-by-example.html)

# 定义 PSR-7 响应类

响应类表示返回给发出原始请求的实体的出站信息。在这种情况下，HTTP 标头起着重要作用，因为我们需要知道客户端请求的格式，通常是在传入的`Accept`标头中。然后，我们需要在响应类中设置适当的`Content-Type`标头以匹配该格式。否则，响应的实际主体将是 HTML、JSON 或其他已请求（并已传递）的内容。

## 如何做...

1.  `Response`类实际上比`Request`类更容易实现，因为我们只关心从服务器返回响应给客户端。此外，它扩展了我们的`Application\MiddleWare\Message`类，其中大部分工作已经完成。因此，唯一剩下的工作就是定义一个`Application\MiddleWare\Response`类。正如您将注意到的，唯一的独特属性是`$statusCode`：

```php
namespace Application\MiddleWare;
use Psr\Http\Message\ { Constants, ResponseInterface, StreamInterface };
class Response extends Message implements ResponseInterface
{
  protected $statusCode;
```

1.  构造函数没有由 PSR-7 定义，但我们为方便起见提供了它，允许开发人员创建一个具有所有部分完整的`Response`实例。我们使用`Message`的方法和`Constants`类的常量来验证参数：

```php
public function __construct($statusCode = NULL,
                            StreamInterface $body = NULL,
                            $headers = NULL,
                            $version = NULL)
{
  $this->body = $body;
  $this->status['code'] = $statusCode ?? Constants::DEFAULT_STATUS_CODE;
  $this->status['reason'] = Constants::STATUS_CODES[$statusCode] ?? '';
  $this->httpHeaders = $headers;
  $this->version = $this->onlyVersion($version);
  if ($statusCode) $this->setStatusCode();
}
```

1.  我们提供了一种很好的方法来设置 HTTP 状态码，而不考虑任何标头，使用`http_response_code()`，从 PHP 5.4 开始可用。由于这项工作是在 PHP 7 上进行的，我们可以放心地知道这个方法是存在的：

```php
public function setStatusCode()
{
  http_response_code($this->getStatusCode());
}
```

1.  否则，有兴趣使用以下方法获取状态码：

```php
public function getStatusCode()
{
  return $this->status['code'];
}
```

1.  与早期的配方中讨论的其他基于 PSR-7 的类一样，我们还定义了一个`with`方法，用于设置状态码并返回当前实例。请注意使用`STATUS_CODES`来确认其存在：

```php
public function withStatus($statusCode, $reasonPhrase = '')
{
  if (!isset(Constants::STATUS_CODES[$statusCode])) {
      throw new InvalidArgumentException(Constants::ERROR_INVALID_STATUS);
  }
  $this->status['code'] = $statusCode;
  $this->status['reason'] = ($reasonPhrase) ? Constants::STATUS_CODES[$statusCode] : NULL;
  $this->setStatusCode();
  return $this;
}
```

1.  最后，我们定义一个返回 HTTP 状态原因的方法，这是一个简短的文本短语，在本例中基于 RFC 7231。请注意使用 PHP 7 的空合并运算符`??`，它返回三个可能选择中的第一个非空项：

```php
public function getReasonPhrase()
{
  return $this->status['reason'] 
    ?? Constants::STATUS_CODES[$this->status['code']] 
    ?? '';
  }
}
```

## 工作原理...

首先，请确保定义了前两个配方中讨论的类。之后，您可以创建另一个简单的服务器程序`chap_09_middleware_server_with_response.php`，该程序设置自动加载并使用适当的类：

```php
<?php
require __DIR__ . '/../Application/Autoload/Loader.php';
Application\Autoload\Loader::init(__DIR__ . '/..');
use Application\MiddleWare\ { Constants, ServerRequest, Response, Stream };
```

然后，您可以定义一个具有键/值对的数组，其中值指向当前目录中用作内容的文本文件：

```php
$data = [
  1 => 'churchill.txt',
  2 => 'gettysburg.txt',
  3 => 'star_trek.txt'
];
```

接下来，在`try...catch`块内，您可以初始化一些变量，初始化服务器请求，并设置临时文件名：

```php
try {

    $body['text'] = 'Initial State';
    $request = new ServerRequest();
    $request->initialize();
    $tempFile = bin2hex(random_bytes(8)) . '.txt';
    $code = 200;
```

之后，检查方法是 GET 还是 POST。如果是 GET，请检查是否传递了`id`参数。如果是，则返回匹配文本文件的正文。否则，返回文本文件列表：

```php
if ($request->getMethod() == Constants::METHOD_GET) {
    $id = $request->getQueryParams()['id'] ?? NULL;
    $id = (int) $id;
    if ($id && $id <= count($data)) {
        $body['text'] = file_get_contents(
        __DIR__ . '/' . $data[$id]);
    } else {
        $body['text'] = $data;
    }
```

否则，返回一个表示成功代码 204 和接收到的请求体大小的响应：

```php
} elseif ($request->getMethod() == Constants::METHOD_POST) {
    $size = $request->getBody()->getSize();
    $body['text'] = $size . ' bytes of data received';
    if ($size) {
        $code = 201;
    } else {
        $code = 204;
    }
}
```

然后，您可以捕获任何异常并报告它们，状态代码为 500：

```php
} catch (Exception $e) {
    $code = 500;
    $body['text'] = 'ERROR: ' . $e->getMessage();
}
```

响应需要包装在流中，以便将正文写入临时文件并将其创建为`Stream`。您还可以将`Content-Type`标头设置为`application/json`并运行`getHeaders()`，这将输出当前设置的标头集。之后，回显响应的正文。对于此示例，您还可以转储`Response`实例以确认它是否正确构造：

```php
try {
    file_put_contents($tempFile, json_encode($body));
    $body = new Stream($tempFile);
    $header[Constants::HEADER_CONTENT_TYPE] = 'application/json';
    $response = new Response($code, $body, $header);
    $response->getHeaders();
    echo $response->getBody()->getContents() . PHP_EOL;
    var_dump($response);
```

最后，捕获任何错误或异常使用`Throwable`，并不要忘记删除临时文件：

```php
} catch (Throwable $e) {
    echo $e->getMessage();
} finally {
   unlink($tempFile);
}
```

要进行测试，只需打开终端窗口，切换到`/path/to/source/for/this/chapter`目录，并运行以下命令：

```php
**php -S localhost:8080**

```

然后，您可以从浏览器调用此程序，添加一个`id`参数。您可能考虑打开开发人员工具以监视响应标头。以下是预期输出的示例。请注意`application/json`的内容类型：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-cb/img/B05314_09_04.jpg)

## 另请参阅

+   有关 PSR 的更多信息，请访问[`www.php-fig.org/psr/`](http://www.php-fig.org/psr/)。

+   以下表总结了撰写时 PSR-7 兼容性的状态。未包括在此表中的框架要么根本不支持 PSR-7，要么缺乏 PSR-7 的文档。

| Framework | 网站 | 注释 |
| --- | --- | --- |
| Slim | [`www.slimframework.com/docs/concepts/value-objects.html`](http://www.slimframework.com/docs/concepts/value-objects.html) | 高 PSR-7 兼容性 |
| Laravel/Lumen | [`lumen.laravel.com/docs/5.2/requests`](https://lumen.laravel.com/docs/5.2/requests) | 高 PSR-7 兼容性 |
| Zend Framework 3/Expressive | [`framework.zend.com/blog/2016-06-28-zend-framework-3.html`](https://framework.zend.com/blog/2016-06-28-zend-framework-3.html) 或 [`zendframework.github.io/zend-expressive/`](https://zendframework.github.io/zend-expressive/) 分别 | 高 PSR-7 兼容性 Also Diactoros, and Straigility |
| Zend Framework 2 | [`github.com/zendframework/zend-psr7bridge`](https://github.com/zendframework/zend-psr7bridge) | 可用的 PSR-7 桥 |
| Symfony | [`symfony.com/doc/current/cookbook/psr7.html`](http://symfony.com/doc/current/cookbook/psr7.html) | 可用的 PSR-7 桥 |
| Joomla | [`www.joomla.org`](https://www.joomla.org) | 有限的 PSR-7 支持 |
| Cake PHP | [`mark-story.com/posts/view/psr7-bridge-for-cakephp`](http://mark-story.com/posts/view/psr7-bridge-for-cakephp) | PSR-7 支持在路线图中，并将使用桥接方法 |

+   已经有许多 PSR-7 中间件类可用。以下表总结了一些较受欢迎的类：

| Middleware | 网站 | 注释 |
| --- | --- | --- |
| Guzzle | [`github.com/guzzle/psr7`](https://github.com/guzzle/psr7) | HTTP 消息库 |
| Relay | [`relayphp.com/`](http://relayphp.com/) | 调度器 |
| Radar | [`github.com/radarphp/Radar.Project`](https://github.com/radarphp/Radar.Project) | 动作/领域/响应者骨架 |
| NegotiationMiddleware | [`github.com/rszrama/negotiation-middleware`](https://github.com/rszrama/negotiation-middleware) | 内容协商 |
| psr7-csrf-middleware | [`packagist.org/packages/schnittstabil/psr7-csrf-middleware`](https://packagist.org/packages/schnittstabil/psr7-csrf-middleware) | 跨站点请求伪造预防 |
| oauth2-server | [`alexbilbie.com/2016/04/league-oauth2-server-version-5-is-out`](http://alexbilbie.com/2016/04/league-oauth2-server-version-5-is-out) | 支持 PSR-7 的 OAuth2 服务器 |
| zend-diactoros | [`zendframework.github.io/zend-diactoros/`](https://zendframework.github.io/zend-diactoros/) | PSR-7 HTTP 消息实现 |
