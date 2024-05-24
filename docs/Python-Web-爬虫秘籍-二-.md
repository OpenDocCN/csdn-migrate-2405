# Python Web 爬虫秘籍（二）

> 原文：[`zh.annas-archive.org/md5/6ba628f13aabe820a089a16eaa190089`](https://zh.annas-archive.org/md5/6ba628f13aabe820a089a16eaa190089)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：处理图像、音频和其他资产

在本章中，我们将涵盖：

+   在网上下载媒体内容

+   使用 urllib 解析 URL 以获取文件名

+   确定 URL 的内容类型

+   从内容类型确定文件扩展名

+   下载并将图像保存到本地文件系统

+   下载并将图像保存到 S3

+   为图像生成缩略图

+   使用 Selenium 进行网站截图

+   使用外部服务对网站进行截图

+   使用 pytessaract 对图像执行 OCR

+   创建视频缩略图

+   将 MP4 视频转换为 MP3

# 介绍

在抓取中的一个常见做法是下载、存储和进一步处理媒体内容（非网页或数据文件）。这些媒体可以包括图像、音频和视频。为了正确地将内容存储在本地（或在 S3 等服务中），我们需要知道媒体类型，并且仅仅信任 URL 中的文件扩展名是不够的。我们将学习如何根据来自 Web 服务器的信息下载和正确表示媒体类型。

另一个常见的任务是生成图像、视频甚至网站页面的缩略图。我们将研究如何生成缩略图并制作网站页面截图的几种技术。这些缩略图经常用作新网站上缩略图链接，以链接到现在存储在本地的抓取媒体。

最后，通常需要能够转码媒体，例如将非 MP4 视频转换为 MP4，或更改视频的比特率或分辨率。另一个场景是从视频文件中提取音频。我们不会讨论视频转码，但我们将使用`ffmpeg`从 MP4 文件中提取 MP3 音频。从那里开始，还可以使用`ffmpeg`转码视频。

# 从网上下载媒体内容

从网上下载媒体内容是一个简单的过程：使用 Requests 或其他库，就像下载 HTML 内容一样。

# 准备工作

解决方案的`util`文件夹中的`urls.py`模块中有一个名为`URLUtility`的类。该类处理本章中的几种场景，包括下载和解析 URL。我们将在这个配方和其他一些配方中使用这个类。确保`modules`文件夹在您的 Python 路径中。此外，此配方的示例位于`04/01_download_image.py`文件中。

# 如何做到这一点

以下是我们如何进行的步骤：

1.  `URLUtility`类可以从 URL 下载内容。配方文件中的代码如下：

```py
import const
from util.urls import URLUtility

util = URLUtility(const.ApodEclipseImage())
print(len(util.data))
```

1.  运行时，您将看到以下输出：

```py
Reading URL: https://apod.nasa.gov/apod/image/1709/BT5643s.jpg
Read 171014 bytes
171014
```

示例读取了`171014`字节的数据。

# 它是如何工作的

URL 被定义为`const`模块中的常量`const.ApodEclipseImage()`：

```py
def ApodEclipseImage():
    return "https://apod.nasa.gov/apod/image/1709/BT5643s.jpg" 
```

`URLUtility`类的构造函数具有以下实现：

```py
def __init__(self, url, readNow=True):
    """ Construct the object, parse the URL, and download now if specified"""
  self._url = url
    self._response = None
  self._parsed = urlparse(url)
    if readNow:
        self.read()
```

构造函数存储 URL，解析它，并使用`read()`方法下载文件。以下是`read()`方法的代码：

```py
def read(self):
    self._response = urllib.request.urlopen(self._url)
    self._data = self._response.read()
```

该函数使用`urlopen`获取响应对象，然后读取流并将其存储为对象的属性。然后可以使用数据属性检索该数据：

```py
@property def data(self):
    self.ensure_response()
    return self._data
```

然后，该代码简单地报告了该数据的长度，值为`171014`。

# 还有更多...

这个类将用于其他任务，比如确定文件的内容类型、文件名和扩展名。接下来我们将研究解析 URL 以获取文件名。

# 使用 urllib 解析 URL 以获取文件名

从 URL 下载内容时，我们经常希望将其保存在文件中。通常情况下，将文件保存在 URL 中找到的文件名中就足够了。但是 URL 由许多片段组成，那么我们如何从 URL 中找到实际的文件名，特别是在文件名后经常有许多参数的情况下？

# 准备工作

我们将再次使用`URLUtility`类来完成这个任务。该配方的代码文件是`04/02_parse_url.py`。

# 如何做到这一点

使用您的 Python 解释器执行配方文件。它将运行以下代码：

```py
util = URLUtility(const.ApodEclipseImage())
print(util.filename_without_ext)
```

这导致以下输出：

```py
Reading URL: https://apod.nasa.gov/apod/image/1709/BT5643s.jpg
Read 171014 bytes
The filename is: BT5643s
```

# 它是如何工作的

在`URLUtility`的构造函数中，调用了`urlib.parse.urlparse`。 以下演示了交互式使用该函数：

```py
>>> parsed = urlparse(const.ApodEclipseImage())
>>> parsed
ParseResult(scheme='https', netloc='apod.nasa.gov', path='/apod/image/1709/BT5643s.jpg', params='', query='', fragment='')
```

`ParseResult`对象包含 URL 的各个组件。 路径元素包含路径和文件名。 对`.filename_without_ext`属性的调用仅返回没有扩展名的文件名：

```py
@property def filename_without_ext(self):
    filename = os.path.splitext(os.path.basename(self._parsed.path))[0]
    return filename
```

对`os.path.basename`的调用仅返回路径的文件名部分（包括扩展名）。 `os.path.splittext()`然后分隔文件名和扩展名，并且该函数返回该元组/列表的第一个元素（文件名）。

# 还有更多...

这似乎有点奇怪，它没有将扩展名作为文件名的一部分返回。 这是因为我们不能假设我们收到的内容实际上与扩展名所暗示的类型匹配。 更准确的是使用 Web 服务器返回的标题来确定这一点。 这是我们下一个配方。

# 确定 URL 的内容类型

当从 Web 服务器获取内容的`GET`请求时，Web 服务器将返回许多标题，其中一个标识了内容的类型，从 Web 服务器的角度来看。 在这个配方中，我们学习如何使用它来确定 Web 服务器认为的内容类型。

# 做好准备

我们再次使用`URLUtility`类。 配方的代码在`04/03_determine_content_type_from_response.py`中。

# 如何做到这一点

我们按以下步骤进行：

1.  执行配方的脚本。 它包含以下代码：

```py
util = URLUtility(const.ApodEclipseImage())
print("The content type is: " + util.contenttype)
```

1.  得到以下结果：

```py
Reading URL: https://apod.nasa.gov/apod/image/1709/BT5643s.jpg
Read 171014 bytes
The content type is: image/jpeg
```

# 它是如何工作的

`.contentype`属性的实现如下：

```py
@property def contenttype(self):
    self.ensure_response()
    return self._response.headers['content-type']
```

`_response`对象的`.headers`属性是一个类似字典的标题类。 `content-type`键将检索服务器指定的`content-type`。 对`ensure_response()`方法的调用只是确保已执行`.read()`函数。

# 还有更多...

响应中的标题包含大量信息。 如果我们更仔细地查看响应的`headers`属性，我们可以看到返回以下标题：

```py
>>> response = urllib.request.urlopen(const.ApodEclipseImage())
>>> for header in response.headers: print(header)
Date
Server
Last-Modified
ETag
Accept-Ranges
Content-Length
Connection
Content-Type
Strict-Transport-Security
```

我们可以看到每个标题的值。

```py
>>> for header in response.headers: print(header + " ==> " + response.headers[header])
Date ==> Tue, 26 Sep 2017 19:31:41 GMT
Server ==> WebServer/1.0
Last-Modified ==> Thu, 31 Aug 2017 20:26:32 GMT
ETag ==> "547bb44-29c06-5581275ce2b86"
Accept-Ranges ==> bytes
Content-Length ==> 171014
Connection ==> close
Content-Type ==> image/jpeg
Strict-Transport-Security ==> max-age=31536000; includeSubDomains
```

这本书中有许多我们不会讨论的内容，但对于不熟悉的人来说，知道它们存在是很好的。

# 从内容类型确定文件扩展名

使用`content-type`标题来确定内容的类型，并确定用于存储内容的扩展名是一个很好的做法。

# 做好准备

我们再次使用了我们创建的`URLUtility`对象。 配方的脚本是`04/04_determine_file_extension_from_contenttype.py`。

# 如何做到这一点

通过运行配方的脚本来进行。

可以使用`.extension`属性找到媒体类型的扩展名：

```py
util = URLUtility(const.ApodEclipseImage())
print("Filename from content-type: " + util.extension_from_contenttype)
print("Filename from url: " + util.extension_from_url)
```

这导致以下输出：

```py
Reading URL: https://apod.nasa.gov/apod/image/1709/BT5643s.jpg
Read 171014 bytes
Filename from content-type: .jpg
Filename from url: .jpg
```

这报告了从文件类型和 URL 确定的扩展名。 这些可能不同，但在这种情况下它们是相同的。

# 它是如何工作的

以下是`.extension_from_contenttype`属性的实现：

```py
@property def extension_from_contenttype(self):
    self.ensure_response()

    map = const.ContentTypeToExtensions()
    if self.contenttype in map:
        return map[self.contenttype]
    return None 
```

第一行确保我们已从 URL 读取响应。 然后，该函数使用在`const`模块中定义的 Python 字典，其中包含内容类型到扩展名的字典：

```py
def ContentTypeToExtensions():
    return {
        "image/jpeg": ".jpg",
  "image/jpg": ".jpg",
  "image/png": ".png"
  }
```

如果内容类型在字典中，则将返回相应的值。 否则，将返回`None`。

注意相应的属性`.extension_from_url`：

```py
@property def extension_from_url(self):
    ext = os.path.splitext(os.path.basename(self._parsed.path))[1]
    return ext
```

这使用与`.filename`属性相同的技术来解析 URL，但是返回代表扩展名而不是基本文件名的`[1]`元素。

# 还有更多...

如前所述，最好使用`content-type`标题来确定用于本地存储文件的扩展名。 除了这里提供的技术之外，还有其他技术，但这是最简单的。

# 下载并将图像保存到本地文件系统

有时在爬取时，我们只是下载和解析数据，比如 HTML，提取一些数据，然后丢弃我们读取的内容。其他时候，我们希望通过将其存储为文件来保留已下载的内容。

# 如何做

这个配方的代码示例在`04/05_save_image_as_file.py`文件中。文件中重要的部分是：

```py
# download the image item = URLUtility(const.ApodEclipseImage())

# create a file writer to write the data FileBlobWriter(expanduser("~")).write(item.filename, item.data)
```

用你的 Python 解释器运行脚本，你将得到以下输出：

```py
Reading URL: https://apod.nasa.gov/apod/image/1709/BT5643s.jpg
Read 171014 bytes
Attempting to write 171014 bytes to BT5643s.jpg:
The write was successful
```

# 工作原理

这个示例只是使用标准的 Python 文件访问函数将数据写入文件。它通过使用标准的写入数据接口以面向对象的方式来实现，使用了`FileBlobWriter`类的基于文件的实现：

```py
""" Implements the IBlobWriter interface to write the blob to a file """   from interface import implements
from core.i_blob_writer import IBlobWriter

class FileBlobWriter(implements(IBlobWriter)):
    def __init__(self, location):
        self._location = location

    def write(self, filename, contents):
        full_filename = self._location + "/" + filename
        print ("Attempting to write {0} bytes to {1}:".format(len(contents), filename))

        with open(full_filename, 'wb') as outfile:
            outfile.write(contents)

        print("The write was successful")
```

该类传递一个表示文件应该放置的目录的字符串。实际上，数据是在稍后调用`.write()`方法时写入的。这个方法合并了文件名和`directory (_location)`，然后打开/创建文件并写入字节。`with`语句确保文件被关闭。

# 还有更多...

这篇文章可以简单地使用一个包装代码的函数来处理。这个对象将在本章中被重复使用。我们可以使用 Python 的鸭子类型，或者只是一个函数，但是接口的清晰度更容易。说到这一点，以下是这个接口的定义：

```py
""" Defines the interface for writing a blob of data to storage """   from interface import Interface

class IBlobWriter(Interface):
   def write(self, filename, contents):
      pass
```

我们还将看到另一个实现这个接口的方法，让我们可以将文件存储在 S3 中。通过这种类型的实现，通过接口继承，我们可以很容易地替换实现。

# 下载并保存图像到 S3

我们已经看到了如何在第三章中将内容写入 S3，*处理数据*。在这里，我们将把这个过程扩展到 IBlobWriter 的接口实现，以便写入 S3。

# 准备工作

这个配方的代码示例在`04/06_save_image_in_s3.py`文件中。还要确保你已经将 AWS 密钥设置为环境变量，这样 Boto 才能验证脚本。

# 如何做

我们按照以下步骤进行：

1.  运行配方的脚本。它将执行以下操作：

```py
# download the image item = URLUtility(const.ApodEclipseImage())

# store it in S3 S3BlobWriter(bucket_name="scraping-apod").write(item.filename, item.data)
```

1.  在 S3 中检查，我们可以看到存储桶已经创建，并且图像已放置在存储桶中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/5abb4f94-3072-4d9a-b868-60ac32c2d295.png)S3 中的图像

# 工作原理

以下是`S3BlobWriter`的实现：

```py
class S3BlobWriter(implements(IBlobWriter)):
    def __init__(self, bucket_name, boto_client=None):
        self._bucket_name = bucket_name

        if self._bucket_name is None:
            self.bucket_name = "/"    # caller can specify a boto client (can reuse and save auth times)
  self._boto_client = boto_client

        # or create a boto client if user did not, use secrets from environment variables
  if self._boto_client is None:
            self._boto_client = boto3.client('s3')

    def write(self, filename, contents):
        # create bucket, and put the object
  self._boto_client.create_bucket(Bucket=self._bucket_name, ACL='public-read')
        self._boto_client.put_object(Bucket=self._bucket_name,
  Key=filename,
  Body=contents,
  ACL="public-read")
```

我们之前在写入 S3 的配方中看到了这段代码。这个类将它整齐地包装成一个可重用的接口实现。创建一个实例时，指定存储桶名称。然后每次调用`.write()`都会保存在同一个存储桶中。

# 还有更多...

S3 在存储桶上提供了一个称为启用网站的功能。基本上，如果你设置了这个选项，存储桶中的内容将通过 HTTP 提供。我们可以将许多图像写入这个目录，然后直接从 S3 中提供它们，而不需要实现一个 Web 服务器！

# 为图像生成缩略图

许多时候，在下载图像时，你不想保存完整的图像，而只想保存缩略图。或者你也可以同时保存完整尺寸的图像和缩略图。在 Python 中，使用 Pillow 库可以很容易地创建缩略图。Pillow 是 Python 图像库的一个分支，包含许多有用的图像处理函数。你可以在[Pillow 官网](https://python-pillow.org)找到更多关于 Pillow 的信息。在这个配方中，我们使用 Pillow 来创建图像缩略图。

# 准备工作

这个配方的脚本是`04/07_create_image_thumbnail.py`。它使用了 Pillow 库，所以确保你已经用 pip 或其他包管理工具将 Pillow 安装到你的环境中。

```py
pip install pillow
```

# 如何做

以下是如何进行配方：

运行配方的脚本。它将执行以下代码：

```py
from os.path import expanduser
import const
from core.file_blob_writer import FileBlobWriter
from core.image_thumbnail_generator import ImageThumbnailGenerator
from util.urls import URLUtility

# download the image and get the bytes img_data = URLUtility(const.ApodEclipseImage()).data

# we will store this in our home folder fw = FileBlobWriter(expanduser("~"))

# Create a thumbnail generator and scale the image tg = ImageThumbnailGenerator(img_data).scale(200, 200)

# write the image to a file fw.write("eclipse_thumbnail.png", tg.bytes)
```

结果将是一个名为`eclipse_thumbnail.png`的文件写入你的主目录。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/bc8c1992-366f-43c9-bcb4-281c5644df69.png)我们创建的缩略图

Pillow 保持宽度和高度的比例一致。

# 工作原理

`ImageThumbnailGenerator`类封装了对 Pillow 的调用，为创建图像缩略图提供了一个非常简单的 API：

```py
import io
from PIL import Image

class ImageThumbnailGenerator():
    def __init__(self, bytes):
        # Create a pillow image with the data provided
  self._image = Image.open(io.BytesIO(bytes))

    def scale(self, width, height):
        # call the thumbnail method to create the thumbnail
  self._image.thumbnail((width, height))
        return self    @property
  def bytes(self):
        # returns the bytes of the pillow image   # save the image to an in memory objects  bytesio = io.BytesIO()
        self._image.save(bytesio, format="png")

```

```py
        # set the position on the stream to 0 and return the underlying data
  bytesio.seek(0)
        return bytesio.getvalue()

```

构造函数传递图像数据并从该数据创建 Pillow 图像对象。通过调用`.thumbnail()`创建缩略图，参数是表示缩略图所需大小的元组。这将调整现有图像的大小，并且 Pillow 会保留纵横比。它将确定图像的较长边并将其缩放到元组中表示该轴的值。此图像的高度大于宽度，因此缩略图的高度为 200 像素，并且宽度相应地缩放（在本例中为 160 像素）。

# 对网站进行截图

一个常见的爬取任务是对网站进行截图。在 Python 中，我们可以使用 selenium 和 webdriver 来创建缩略图。

# 准备就绪

此示例的脚本是`04/08_create_website_screenshot.py`。还要确保您的路径中有 selenium，并且已安装 Python 库。

# 操作步骤

运行该示例的脚本。脚本中的代码如下：

```py
from core.website_screenshot_generator import WebsiteScreenshotGenerator
from core.file_blob_writer import FileBlobWriter
from os.path import expanduser

# get the screenshot image_bytes = WebsiteScreenshotGenerator().capture("http://espn.go.com", 500, 500).image_bytes

# save it to a file FileBlobWriter(expanduser("~")).write("website_screenshot.png", image_bytes)
```

创建一个`WebsiteScreenshotGenerator`对象，然后调用其 capture 方法，传递要捕获的网站的 URL 和图像的所需宽度（以像素为单位）。

这将创建一个 Pillow 图像，可以使用`.image`属性访问，并且可以直接使用`.image_bytes`访问图像的字节。此脚本获取这些字节并将它们写入到您的主目录中的`website_screenshot.png`文件中。

您将从此脚本中看到以下输出：

```py
Connected to pydev debugger (build 162.1967.10)
Capturing website screenshot of: http://espn.go.com
Got a screenshot with the following dimensions: (500, 7416)
Cropped the image to: 500 500
Attempting to write 217054 bytes to website_screenshot.png:
The write was successful
```

我们的结果图像如下（图像的内容会有所不同）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/b9c8c756-e789-43ae-a20b-d90e7b146181.png)网页截图

# 工作原理

以下是`WebsiteScreenshotGenerator`类的代码：

```py
class WebsiteScreenshotGenerator():
    def __init__(self):
        self._screenshot = None   def capture(self, url, width, height, crop=True):
        print ("Capturing website screenshot of: " + url)
        driver = webdriver.PhantomJS()

        if width and height:
            driver.set_window_size(width, height)

        # go and get the content at the url
  driver.get(url)

        # get the screenshot and make it into a Pillow Image
  self._screenshot = Image.open(io.BytesIO(driver.get_screenshot_as_png()))
        print("Got a screenshot with the following dimensions: {0}".format(self._screenshot.size))

        if crop:
            # crop the image
  self._screenshot = self._screenshot.crop((0,0, width, height))
            print("Cropped the image to: {0} {1}".format(width, height))

        return self    @property
  def image(self):
        return self._screenshot

    @property
  def image_bytes(self):
        bytesio = io.BytesIO()
        self._screenshot.save(bytesio, "PNG")
        bytesio.seek(0)
        return bytesio.getvalue()
```

调用`driver.get_screenshot_as_png()`完成了大部分工作。它将页面呈现为 PNG 格式的图像并返回图像的字节。然后将这些数据转换为 Pillow 图像对象。

请注意输出中来自 webdriver 的图像高度为 7416 像素，而不是我们指定的 500 像素。PhantomJS 渲染器将尝试处理无限滚动的网站，并且通常不会将截图限制在窗口给定的高度上。

要实际使截图达到指定的高度，请将裁剪参数设置为`True`（默认值）。然后，此代码将使用 Pillow Image 的裁剪方法设置所需的高度。如果使用`crop=False`运行此代码，则结果将是高度为 7416 像素的图像。

# 使用外部服务对网站进行截图

前一个示例使用了 selenium、webdriver 和 PhantomJS 来创建截图。这显然需要安装这些软件包。如果您不想安装这些软件包，但仍想制作网站截图，则可以使用许多可以截图的网络服务之一。在此示例中，我们将使用[www.screenshotapi.io](http://www.screenshotapi.io)上的服务来创建截图。

# 准备就绪

首先，前往`www.screenshotapi.io`注册一个免费账户：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/ec4f1644-7736-4e42-ad3f-6f1b12bf1cc0.png)免费账户注册的截图

创建账户后，继续获取 API 密钥。这将需要用于对其服务进行身份验证：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/4834f589-e457-4f33-aac9-c809451b33c5.png)API 密钥

# 操作步骤

此示例的脚本是`04/09_screenshotapi.py`。运行此脚本将生成一个截图。以下是代码，结构与前一个示例非常相似：

```py
from core.website_screenshot_with_screenshotapi import WebsiteScreenshotGenerator
from core.file_blob_writer import FileBlobWriter
from os.path import expanduser

# get the screenshot image_bytes = WebsiteScreenshotGenerator("bd17a1e1-db43-4686-9f9b-b72b67a5535e")\
    .capture("http://espn.go.com", 500, 500).image_bytes

# save it to a file FileBlobWriter(expanduser("~")).write("website_screenshot.png", image_bytes)
```

与前一个示例的功能区别在于，我们使用了不同的`WebsiteScreenshotGenerator`实现。这个来自`core.website_screenshot_with_screenshotapi`模块。

运行时，以下内容将输出到控制台：

```py
Sending request: http://espn.go.com
{"status":"ready","key":"2e9a40b86c95f50ad3f70613798828a8","apiCreditsCost":1}
The image key is: 2e9a40b86c95f50ad3f70613798828a8
Trying to retrieve: https://api.screenshotapi.io/retrieve
Downloading image: https://screenshotapi.s3.amazonaws.com/captures/2e9a40b86c95f50ad3f70613798828a8.png
Saving screenshot to: downloaded_screenshot.png2e9a40b86c95f50ad3f70613798828a8
Cropped the image to: 500 500
Attempting to write 209197 bytes to website_screenshot.png:
The write was successful
```

并给我们以下图像：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/6e8e5801-80c3-4d34-a228-f6633af08c75.png)`screenshotapi.io`的网站截图

# 它是如何工作的

以下是此`WebsiteScreenshotGenerator`的代码：

```py
class WebsiteScreenshotGenerator:
    def __init__(self, apikey):
        self._screenshot = None
  self._apikey = apikey

    def capture(self, url, width, height, crop=True):
        key = self.beginCapture(url, "{0}x{1}".format(width, height), "true", "firefox", "true")

        print("The image key is: " + key)

        timeout = 30
  tCounter = 0
  tCountIncr = 3    while True:
            result = self.tryRetrieve(key)
            if result["success"]:
                print("Saving screenshot to: downloaded_screenshot.png" + key)

                bytes=result["bytes"]
                self._screenshot = Image.open(io.BytesIO(bytes))

                if crop:
                    # crop the image
  self._screenshot = self._screenshot.crop((0, 0, width, height))
                    print("Cropped the image to: {0} {1}".format(width, height))
                break    tCounter += tCountIncr
            print("Screenshot not yet ready.. waiting for: " + str(tCountIncr) + " seconds.")
            time.sleep(tCountIncr)
            if tCounter > timeout:
                print("Timed out while downloading: " + key)
                break
 return self    def beginCapture(self, url, viewport, fullpage, webdriver, javascript):
        serverUrl = "https://api.screenshotapi.io/capture"
  print('Sending request: ' + url)
        headers = {'apikey': self._apikey}
        params = {'url': urllib.parse.unquote(url).encode('utf8'), 'viewport': viewport, 'fullpage': fullpage,
  'webdriver': webdriver, 'javascript': javascript}
        result = requests.post(serverUrl, data=params, headers=headers)
        print(result.text)
        json_results = json.loads(result.text)
        return json_results['key']

    def tryRetrieve(self, key):
        url = 'https://api.screenshotapi.io/retrieve'
  headers = {'apikey': self._apikey}
        params = {'key': key}
        print('Trying to retrieve: ' + url)
        result = requests.get(url, params=params, headers=headers)

        json_results = json.loads(result.text)
        if json_results["status"] == "ready":
            print('Downloading image: ' + json_results["imageUrl"])
            image_result = requests.get(json_results["imageUrl"])
            return {'success': True, 'bytes': image_result.content}
        else:
            return {'success': False}

    @property
  def image(self):
        return self._screenshot

    @property
  def image_bytes(self):
        bytesio = io.BytesIO()
        self._screenshot.save(bytesio, "PNG")
        bytesio.seek(0)
        return bytesio.getvalue()
```

`screenshotapi.io` API 是一个 REST API。有两个不同的端点：

+   [`api.screenshotapi.io/capture`](https://api.screenshotapi.io/capture)

+   [`api.screenshotapi.io/retrieve`](https://api.screenshotapi.io/retrieve)

首先调用第一个端点，并将 URL 和其他参数传递给其服务。成功执行后，此 API 将返回一个密钥，可用于在另一个端点上检索图像。截图是异步执行的，我们需要不断调用使用从捕获端点返回的密钥的“检索”API。当截图完成时，此端点将返回`ready`状态值。代码简单地循环，直到设置为此状态，发生错误或代码超时。

当快照可用时，API 会在“检索”响应中返回图像的 URL。然后，代码会检索此图像，并从接收到的数据构造一个 Pillow 图像对象。

# 还有更多...

`screenshotapi.io` API 有许多有用的参数。其中几个允许您调整要使用的浏览器引擎（Firefox、Chrome 或 PhantomJS）、设备仿真以及是否在网页中执行 JavaScript。有关这些选项和 API 的更多详细信息，请访问[`docs.screenshotapi.io/rest-api/`](http://docs.screenshotapi.io/rest-api)。

# 使用 pytesseract 对图像执行 OCR

可以使用 pytesseract 库从图像中提取文本。在本示例中，我们将使用 pytesseract 从图像中提取文本。Tesseract 是由 Google 赞助的开源 OCR 库。源代码在这里可用：[`github.com/tesseract-ocr/tesseract`](https://github.com/tesseract-ocr/tesseract)，您还可以在那里找到有关该库的更多信息。pytesseract 是一个提供了 Python API 的薄包装器，为可执行文件提供了 Python API。

# 准备工作

确保您已安装 pytesseract：

```py
pip install pytesseract
```

您还需要安装 tesseract-ocr。在 Windows 上，有一个可执行安装程序，您可以在此处获取：`https://github.com/tesseract-ocr/tesseract/wiki/4.0-with-LSTM#400-alpha-for-windows`。在 Linux 系统上，您可以使用`apt-get`：

```py
sudo apt-get tesseract-ocr
```

在 Mac 上安装最简单的方法是使用 brew：

```py
brew install tesseract
```

此配方的代码位于`04/10_perform_ocr.py`中。

# 如何做

执行该配方的脚本。脚本非常简单：

```py
import pytesseract as pt
from PIL import Image

img = Image.open("textinimage.png")
text = pt.image_to_string(img)
print(text)
```

将要处理的图像是以下图像：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/1ede956f-a997-4723-8f79-39bdd0d1d30f.png)我们将进行 OCR 的图像

脚本给出以下输出：

```py
This is an image containing text.
And some numbers 123456789

And also special characters: !@#$%"&*(_+
```

# 它是如何工作的

首先将图像加载为 Pillow 图像对象。我们可以直接将此对象传递给 pytesseract 的`image_to_string()`函数。该函数在图像上运行 tesseract 并返回它找到的文本。

# 还有更多...

在爬取应用程序中使用 OCR 的主要目的之一是解决基于文本的验证码。我们不会涉及验证码解决方案，因为它们可能很麻烦，而且也在其他 Packt 标题中有记录。

# 创建视频缩略图

您可能希望为从网站下载的视频创建缩略图。这些可以用于显示多个视频缩略图的页面，并允许您单击它们观看特定视频。

# 准备工作

此示例将使用一个名为 ffmpeg 的工具。ffmpeg 可以在 www.ffmpeg.org 上找到。根据您的操作系统的说明进行下载和安装。

# 如何做

示例脚本位于`04/11_create_video_thumbnail.py`中。它包括以下代码：

```py
import subprocess
video_file = 'BigBuckBunny.mp4' thumbnail_file = 'thumbnail.jpg' subprocess.call(['ffmpeg', '-i', video_file, '-ss', '00:01:03.000', '-vframes', '1', thumbnail_file, "-y"])
```

运行时，您将看到来自 ffmpeg 的输出：

```py
 built with Apple LLVM version 8.1.0 (clang-802.0.42)
 configuration: --prefix=/usr/local/Cellar/ffmpeg/3.3.4 --enable-shared --enable-pthreads --enable-gpl --enable-version3 --enable-hardcoded-tables --enable-avresample --cc=clang --host-cflags= --host-ldflags= --enable-libmp3lame --enable-libx264 --enable-libxvid --enable-opencl --enable-videotoolbox --disable-lzma --enable-vda
 libavutil 55\. 58.100 / 55\. 58.100
 libavcodec 57\. 89.100 / 57\. 89.100
 libavformat 57\. 71.100 / 57\. 71.100
 libavdevice 57\. 6.100 / 57\. 6.100
 libavfilter 6\. 82.100 / 6\. 82.100
 libavresample 3\. 5\. 0 / 3\. 5\. 0
 libswscale 4\. 6.100 / 4\. 6.100
 libswresample 2\. 7.100 / 2\. 7.100
 libpostproc 54\. 5.100 / 54\. 5.100
Input #0, mov,mp4,m4a,3gp,3g2,mj2, from 'BigBuckBunny.mp4':
 Metadata:
 major_brand : isom
 minor_version : 512
 compatible_brands: mp41
 creation_time : 1970-01-01T00:00:00.000000Z
 title : Big Buck Bunny
 artist : Blender Foundation
 composer : Blender Foundation
 date : 2008
 encoder : Lavf52.14.0
 Duration: 00:09:56.46, start: 0.000000, bitrate: 867 kb/s
 Stream #0:0(und): Video: h264 (Constrained Baseline) (avc1 / 0x31637661), yuv420p, 320x180 [SAR 1:1 DAR 16:9], 702 kb/s, 24 fps, 24 tbr, 24 tbn, 48 tbc (default)
 Metadata:
 creation_time : 1970-01-01T00:00:00.000000Z
 handler_name : VideoHandler
 Stream #0:1(und): Audio: aac (LC) (mp4a / 0x6134706D), 48000 Hz, stereo, fltp, 159 kb/s (default)
 Metadata:
 creation_time : 1970-01-01T00:00:00.000000Z
 handler_name : SoundHandler
Stream mapping:
 Stream #0:0 -> #0:0 (h264 (native) -> mjpeg (native))
Press [q] to stop, [?] for help
[swscaler @ 0x7fb50b103000] deprecated pixel format used, make sure you did set range correctly
Output #0, image2, to 'thumbnail.jpg':
 Metadata:
 major_brand : isom
 minor_version : 512
 compatible_brands: mp41
 date : 2008
 title : Big Buck Bunny
 artist : Blender Foundation
 composer : Blender Foundation
 encoder : Lavf57.71.100
 Stream #0:0(und): Video: mjpeg, yuvj420p(pc), 320x180 [SAR 1:1 DAR 16:9], q=2-31, 200 kb/s, 24 fps, 24 tbn, 24 tbc (default)
 Metadata:
 creation_time : 1970-01-01T00:00:00.000000Z
 handler_name : VideoHandler
 encoder : Lavc57.89.100 mjpeg
 Side data:
 cpb: bitrate max/min/avg: 0/0/200000 buffer size: 0 vbv_delay: -1
frame= 1 fps=0.0 q=4.0 Lsize=N/A time=00:00:00.04 bitrate=N/A speed=0.151x 
video:8kB audio:0kB subtitle:0kB other streams:0kB global headers:0kB muxing overhead: unknown
```

输出的 JPG 文件将是以下 JPG 图像：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/c9568a21-3200-4c2b-ad42-12ad7f7b92e4.jpg)从视频创建的缩略图

# 它是如何工作的

`.ffmpeg`文件实际上是一个可执行文件。代码将以下 ffmpeg 命令作为子进程执行：

```py
ffmpeg -i BigBuckBunny.mp4 -ss 00:01:03.000 -frames:v 1 thumbnail.jpg -y
```

输入文件是`BigBuckBunny.mp4`。`-ss`选项告诉我们要检查视频的位置。`-frames:v`表示我们要提取一个帧。最后，我们告诉`ffmpeg`将该帧写入`thumbnail.jpg`（`-y`确认覆盖现有文件）。

# 还有更多...

ffmpeg 是一个非常多才多艺和强大的工具。我曾经创建过一个爬虫，它会爬取并找到媒体（实际上是在网站上播放的商业广告），并将它们存储在数字档案中。然后，爬虫会通过消息队列发送消息，这些消息会被一组服务器接收，它们的唯一工作就是运行 ffmpeg 将视频转换为许多不同的格式、比特率，并创建缩略图。从那时起，更多的消息将被发送给审计员，使用一个前端应用程序来检查内容是否符合广告合同条款。了解 ffmeg，它是一个很棒的工具。

# 将 MP4 视频转换为 MP3

现在让我们来看看如何将 MP4 视频中的音频提取为 MP3 文件。你可能想这样做的原因包括想要携带视频的音频（也许是音乐视频），或者你正在构建一个爬虫/媒体收集系统，它还需要音频与视频分开。

这个任务可以使用`moviepy`库来完成。`moviepy`是一个很棒的库，可以让你对视频进行各种有趣的处理。其中一个功能就是提取音频为 MP3。

# 准备工作

确保你的环境中安装了 moviepy：

```py
pip install moviepy
```

我们还需要安装 ffmpeg，这是我们在上一个示例中使用过的，所以你应该已经满足了这个要求。

# 如何操作

演示将视频转换为 MP3 的代码在`04/12_rip_mp3_from_mp4.py`中。`moviepy`使这个过程变得非常容易。

1.  以下是在上一个示例中下载的 MP4 文件的提取：

```py
import moviepy.editor as mp
clip = mp.VideoFileClip("BigBuckBunny.mp4")
clip.audio.write_audiofile("movie_audio.mp3")
```

1.  当运行时，你会看到输出，比如下面的内容，因为文件正在被提取。这只花了几秒钟：

```py
[MoviePy] Writing audio in movie_audio.mp3
100%|██████████| 17820/17820 [00:16<00:00, 1081.67it/s]
[MoviePy] Done.
```

1.  完成后，你将得到一个 MP3 文件：

```py
# ls -l *.mp3 -rw-r--r--@ 1 michaelheydt  staff  12931074 Sep 27 21:44 movie_audio.mp3
```

# 还有更多...

有关 moviepy 的更多信息，请查看项目网站[`zulko.github.io/moviepy/`](http://zulko.github.io/moviepy/)。


# 第五章：抓取 - 行为准则

在本章中，我们将涵盖：

+   抓取的合法性和有礼貌的抓取

+   尊重 robots.txt

+   使用站点地图进行爬行

+   带延迟的爬行

+   使用可识别的用户代理

+   设置每个域的并发请求数量

+   使用自动节流

+   缓存响应

# 介绍

虽然您在技术上可以抓取任何网站，但重要的是要知道抓取是否合法。我们将讨论抓取的法律问题，探讨一般的法律原则，并了解有礼貌地抓取和最大程度地减少对目标网站的潜在损害的最佳做法。

# 抓取的合法性和有礼貌的抓取

这个配方中没有真正的代码。这只是对涉及抓取的法律问题的一些概念的阐述。我不是律师，所以不要把我在这里写的任何东西当作法律建议。我只是指出在使用抓取器时需要关注的一些事情。

# 准备就绪

抓取的合法性分为两个问题：

+   内容所有权

+   拒绝服务

基本上，网上发布的任何内容都是公开阅读的。每次加载页面时，您的浏览器都会从网络服务器下载内容并将其可视化呈现给您。因此，在某种意义上，您和您的浏览器已经在网上查看任何内容。由于网络的性质，因为有人在网上公开发布内容，他们本质上是在要求您获取这些信息，但通常只是为了特定目的。

大问题在于创建直接寻找并复制互联网上的*事物*的自动化工具，*事物*可以是数据、图像、视频或音乐 - 基本上是由他人创建并代表对创建者或所有者有价值的东西。当明确复制项目供您个人使用时，这些项目可能会产生问题，并且在复制并将其用于您或他人的利益时，可能会更有可能产生问题。

视频、书籍、音乐和图像是一些明显引起关注的项目，涉及制作个人或商业用途的副本的合法性。一般来说，如果您从无需授权访问或需要付费访问内容的开放网站（如不需要授权访问或需要付费访问内容的网站）上抓取此类内容，那么您就没问题。还有*公平使用*规则允许在某些情况下重复使用内容，例如在课堂场景中共享少量文件，其中发布供人们学习的知识并没有真正的经济影响。

从网站上抓取*数据*通常是一个更加模糊的问题。我的意思是作为服务提供的信息。从我的经验来看，一个很好的例子是能源价格，这些价格发布在供应商的网站上。这些通常是为了方便客户而提供的，而不是供您自由抓取并将数据用于自己的商业分析服务。如果您只是为了非公开数据库而收集数据，或者只是为了自己的使用而收集数据，那么可能没问题。但是，如果您使用该数据库来驱动自己的网站并以自己的名义分享该内容，那么您可能需要小心。

重点是，查看网站的免责声明/服务条款，了解您可以如何使用这些信息。这应该有记录，但如果没有，那并不意味着您可以肆意妄为。始终要小心并运用常识，因为您正在为自己的目的获取他人的内容。

另一个关注点是我归为拒绝服务的概念，它涉及到收集信息的实际过程以及你收集信息的频率。在网站上手动阅读内容的过程与编写自动机器人不断骚扰网络服务器以获取内容的过程有很大的不同。如果访问频率过高，可能会拒绝其他合法用户访问内容，从而拒绝为他们提供服务。这也可能会增加内容的主机的成本，增加他们的带宽成本，甚至是运行服务器的电费。

一个良好管理的网站将识别这些重复和频繁的访问，并使用诸如基于 IP 地址、标头和 cookie 的规则的 Web 应用程序防火墙关闭它们。在其他情况下，这些可能会被识别，并联系您的 ISP 要求您停止执行这些任务。请记住，您永远不是真正匿名的，聪明的主机可以找出您是谁，确切地知道您访问了什么内容以及何时访问。

# 如何做到这一点

那么，你如何成为一个好的爬虫呢？在本章中，我们将涵盖几个因素：

+   您可以从尊重`robots.txt`文件开始

+   不要爬取您在网站上找到的每个链接，只爬取站点地图中给出的链接。

+   限制您的请求，就像汉·索洛对丘巴卡说的那样：放轻松；或者，不要看起来像您在重复爬取内容

+   让自己被网站识别

# 尊重 robots.txt

许多网站希望被爬取。这是兽性的本质：Web 主机将内容放在其网站上供人类查看。但同样重要的是其他计算机也能看到内容。一个很好的例子是搜索引擎优化（SEO）。SEO 是一个过程，您实际上设计您的网站以便被 Google 等搜索引擎的爬虫爬取，因此您实际上是在鼓励爬取。但与此同时，发布者可能只希望网站的特定部分被爬取，并告诉爬虫不要爬取网站的某些部分，要么是因为不适合分享，要么是因为不重要而浪费了 Web 服务器资源。

通常，您被允许和不被允许爬取的规则包含在大多数网站上的一个名为`robots.txt`的文件中。`robots.txt`是一个可读但可解析的文件，可用于识别您被允许和不被允许爬取的位置。

`robots.txt`文件的格式不幸地不是标准的，任何人都可以进行自己的修改，但是对于格式有很强的共识。`robots.txt`文件通常位于站点的根 URL。为了演示`robots.txt`文件，以下代码包含了亚马逊在[`amazon.com/robots.txt`](http://amazon.com/robots.txt)上提供的摘录。我编辑了它，只显示了重要的概念：

```py
User-agent: *
Disallow: /exec/obidos/account-access-login
Disallow: /exec/obidos/change-style
Disallow: /exec/obidos/flex-sign-in
Disallow: /exec/obidos/handle-buy-box
Disallow: /exec/obidos/tg/cm/member/
Disallow: /gp/aw/help/id=sss
Disallow: /gp/cart
Disallow: /gp/flex

...

Allow: /wishlist/universal*
Allow: /wishlist/vendor-button*
Allow: /wishlist/get-button*

...

User-agent: Googlebot
Disallow: /rss/people/*/reviews
Disallow: /gp/pdp/rss/*/reviews
Disallow: /gp/cdp/member-reviews/
Disallow: /gp/aw/cr/

...
Allow: /wishlist/universal*
Allow: /wishlist/vendor-button*
Allow: /wishlist/get-button*

```

可以看到文件中有三个主要元素：

+   用户代理声明，以下行直到文件结束或下一个用户代理声明将被应用

+   允许爬取的一组 URL

+   禁止爬取的一组 URL

语法实际上非常简单，Python 库存在以帮助我们实现`robots.txt`中包含的规则。我们将使用`reppy`库来尊重`robots.txt`。

# 准备工作

让我们看看如何使用`reppy`库来演示`robots.txt`。有关`reppy`的更多信息，请参阅其 GitHub 页面[`github.com/seomoz/reppy`](https://github.com/seomoz/reppy)。

可以这样安装`reppy`：

```py
pip install reppy
```

但是，我发现在我的 Mac 上安装时出现了错误，需要以下命令：

```py
CFLAGS=-stdlib=libc++ pip install reppy
```

在 Google 上搜索`robots.txt` Python 解析库的一般信息通常会引导您使用 robotparser 库。此库适用于 Python 2.x。对于 Python 3，它已移至`urllib`库。但是，我发现该库在特定情况下报告不正确的值。我将在我们的示例中指出这一点。

# 如何做到这一点

要运行该示例，请执行`05/01_sitemap.py`中的代码。脚本将检查 amazon.com 上是否允许爬取多个 URL。运行时，您将看到以下输出：

```py
True: http://www.amazon.com/
False: http://www.amazon.com/gp/dmusic/
True: http://www.amazon.com/gp/dmusic/promotions/PrimeMusic/
False: http://www.amazon.com/gp/registry/wishlist/
```

# 它是如何工作的

1.  脚本首先通过导入`reppy.robots`开始：

```py
from reppy.robots import Robots
```

1.  然后，代码使用`Robots`来获取 amazon.com 的`robots.txt`。

```py
url = "http://www.amazon.com" robots = Robots.fetch(url + "/robots.txt")
```

1.  使用获取的内容，脚本检查了几个 URL 的可访问性：

```py
paths = [
  '/',
  '/gp/dmusic/', '/gp/dmusic/promotions/PrimeMusic/',
 '/gp/registry/wishlist/'  ]   for path in paths:
  print("{0}: {1}".format(robots.allowed(path, '*'), url + path))
```

此代码的结果如下：

```py
True: http://www.amazon.com/
False: http://www.amazon.com/gp/dmusic/
True: http://www.amazon.com/gp/dmusic/promotions/PrimeMusic/
False: http://www.amazon.com/gp/registry/wishlist/
```

对`robots.allowed`的调用给出了 URL 和用户代理。它根据 URL 是否允许爬取返回`True`或`False`。在这种情况下，指定的 URL 的结果为 True、False、True 和 False。让我们看看如何。

/ URL 在`robots.txt`中没有条目，因此默认情况下是允许的。但是，在*用户代理组下的文件中有以下两行：

```py
Disallow: /gp/dmusic/
Allow: /gp/dmusic/promotions/PrimeMusic
```

不允许/gp/dmusic，因此返回 False。/gp/dmusic/promotions/PrimeMusic 是明确允许的。如果未指定 Allowed:条目，则 Disallow:/gp/dmusic/行也将禁止从/gp/dmusic/进一步的任何路径。这基本上表示以/gp/dmusic/开头的任何 URL 都是不允许的，除了允许爬取/gp/dmusic/promotions/PrimeMusic。

在使用`robotparser`库时存在差异。`robotparser`报告`/gp/dmusic/promotions/PrimeMusic`是不允许的。该库未正确处理此类情况，因为它在第一次匹配时停止扫描`robots.txt`，并且不会进一步查找文件以寻找此类覆盖。

# 还有更多...

首先，有关`robots.txt`的详细信息，请参阅[`developers.google.com/search/reference/robots_txt`](https://developers.google.com/search/reference/robots_txt)。

请注意，并非所有站点都有`robots.txt`，其缺失并不意味着您有权自由爬取所有内容。

此外，`robots.txt`文件可能包含有关在网站上查找站点地图的信息。我们将在下一个示例中检查这些站点地图。

Scrapy 还可以读取`robots.txt`并为您找到站点地图。

# 使用站点地图进行爬行

站点地图是一种允许网站管理员通知搜索引擎有关可用于爬取的网站上的 URL 的协议。网站管理员希望使用此功能，因为他们实际上希望他们的信息被搜索引擎爬取。网站管理员希望使该内容可通过搜索引擎找到，至少通过搜索引擎。但您也可以利用这些信息。

站点地图列出了站点上的 URL，并允许网站管理员指定有关每个 URL 的其他信息：

+   上次更新时间

+   内容更改的频率

+   URL 在与其他 URL 的关系中有多重要

站点地图在以下情况下很有用：

+   网站的某些区域无法通过可浏览的界面访问；也就是说，您无法访问这些页面

+   Ajax、Silverlight 或 Flash 内容通常不会被搜索引擎处理

+   网站非常庞大，网络爬虫有可能忽略一些新的或最近更新的内容

+   当网站具有大量孤立或链接不良的页面时

+   当网站具有较少的外部链接时

站点地图文件具有以下结构：

```py
<?xml version="1.0" encoding="utf-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" 
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
    <url>
        <loc>http://example.com/</loc>
        <lastmod>2006-11-18</lastmod>
        <changefreq>daily</changefreq>
        <priority>0.8</priority>
    </url>
</urlset>
```

站点中的每个 URL 都将用`<url></url>`标签表示，所有这些标签都包裹在外部的`<urlset></urlset>`标签中。始终会有一个指定 URL 的`<loc></loc>`标签。其他三个标签是可选的。

网站地图文件可能非常庞大，因此它们经常被分成多个文件，然后由单个网站地图索引文件引用。该文件的格式如下：

```py
<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
   <sitemap>
      <loc>http://www.example.com/sitemap1.xml.gz</loc>
      <lastmod>2014-10-01T18:23:17+00:00</lastmod>
   </sitemap>
</sitemapindex>
```

在大多数情况下，`sitemap.xml` 文件位于域的根目录下。例如，对于 nasa.gov，它是[`www.nasa.gov/sitemap.xml`](https://www.nasa.gov/sitemap.xml)。但请注意，这不是一个标准，不同的网站可能在不同的位置拥有地图或地图。

特定网站的网站地图也可能位于该网站的 `robots.txt` 文件中。例如，microsoft.com 的 `robots.txt` 文件以以下内容结尾：

```py
Sitemap: https://www.microsoft.com/en-us/explore/msft_sitemap_index.xml
Sitemap: https://www.microsoft.com/learning/sitemap.xml
Sitemap: https://www.microsoft.com/en-us/licensing/sitemap.xml
Sitemap: https://www.microsoft.com/en-us/legal/sitemap.xml
Sitemap: https://www.microsoft.com/filedata/sitemaps/RW5xN8
Sitemap: https://www.microsoft.com/store/collections.xml
Sitemap: https://www.microsoft.com/store/productdetailpages.index.xml
```

因此，要获取 microsoft.com 的网站地图，我们首先需要读取 `robots.txt` 文件并提取该信息。

现在让我们来看看如何解析网站地图。

# 准备工作

你所需要的一切都在 `05/02_sitemap.py` 脚本中，以及与其在同一文件夹中的 `sitemap.py` 文件。`sitemap.py` 文件实现了一个基本的网站地图解析器，我们将在主脚本中使用它。在这个例子中，我们将获取 nasa.gov 的网站地图数据。

# 如何做

首先执行 `05/02_sitemap.py` 文件。确保相关的 `sitemap.py` 文件与其在同一目录或路径下。运行后，几秒钟后，你将会得到类似以下的输出：

```py
Found 35511 urls
{'lastmod': '2017-10-11T18:23Z', 'loc': 'http://www.nasa.gov/centers/marshall/history/this-week-in-nasa-history-apollo-7-launches-oct-11-1968.html', 'tag': 'url'}
{'lastmod': '2017-10-11T18:22Z', 'loc': 'http://www.nasa.gov/feature/researchers-develop-new-tool-to-evaluate-icephobic-materials', 'tag': 'url'}
{'lastmod': '2017-10-11T17:38Z', 'loc': 'http://www.nasa.gov/centers/ames/entry-systems-vehicle-development/roster.html', 'tag': 'url'}
{'lastmod': '2017-10-11T17:38Z', 'loc': 'http://www.nasa.gov/centers/ames/entry-systems-vehicle-development/about.html', 'tag': 'url'}
{'lastmod': '2017-10-11T17:22Z', 'loc': 'http://www.nasa.gov/centers/ames/earthscience/programs/MMS/instruments', 'tag': 'url'}
{'lastmod': '2017-10-11T18:15Z', 'loc': 'http://www.nasa.gov/centers/ames/earthscience/programs/MMS/onepager', 'tag': 'url'}
{'lastmod': '2017-10-11T17:10Z', 'loc': 'http://www.nasa.gov/centers/ames/earthscience/programs/MMS', 'tag': 'url'}
{'lastmod': '2017-10-11T17:53Z', 'loc': 'http://www.nasa.gov/feature/goddard/2017/nasa-s-james-webb-space-telescope-and-the-big-bang-a-short-qa-with-nobel-laureate-dr-john', 'tag': 'url'}
{'lastmod': '2017-10-11T17:38Z', 'loc': 'http://www.nasa.gov/centers/ames/entry-systems-vehicle-development/index.html', 'tag': 'url'}
{'lastmod': '2017-10-11T15:21Z', 'loc': 'http://www.nasa.gov/feature/mark-s-geyer-acting-deputy-associate-administrator-for-technical-human-explorations-and-operations', 'tag': 'url'}
```

程序在所有 nasa.gov 的网站地图中找到了 35,511 个 URL！代码只打印了前 10 个，因为输出量会相当大。使用这些信息来初始化对所有这些 URL 的爬取肯定需要相当长的时间！

但这也是网站地图的美妙之处。许多，如果不是所有的结果都有一个 `lastmod` 标签，告诉你与该关联 URL 末端的内容上次修改的时间。如果你正在实现一个有礼貌的爬虫来爬取 nasa.gov，你会想把这些 URL 及其时间戳保存在数据库中，然后在爬取该 URL 之前检查内容是否实际上已经改变，如果没有改变就不要爬取。

现在让我们看看这实际是如何工作的。

# 工作原理

该方法的工作如下：

1.  脚本开始调用 `get_sitemap()`：

```py
map = sitemap.get_sitemap("https://www.nasa.gov/sitemap.xml")
```

1.  给定一个指向 sitemap.xml 文件（或任何其他文件 - 非压缩）的 URL。该实现简单地获取 URL 处的内容并返回它：

```py
def get_sitemap(url):
  get_url = requests.get(url)    if get_url.status_code == 200:
  return get_url.text
    else:
  print ('Unable to fetch sitemap: %s.' % url) 
```

1.  大部分工作是通过将该内容传递给 `parse_sitemap()` 来完成的。在 nasa.gov 的情况下，这个网站地图包含以下内容，即网站地图索引文件：

```py
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="//www.nasa.gov/sitemap.xsl"?>
<sitemapindex >
<sitemap><loc>http://www.nasa.gov/sitemap-1.xml</loc><lastmod>2017-10-11T19:30Z</lastmod></sitemap>
<sitemap><loc>http://www.nasa.gov/sitemap-2.xml</loc><lastmod>2017-10-11T19:30Z</lastmod></sitemap>
<sitemap><loc>http://www.nasa.gov/sitemap-3.xml</loc><lastmod>2017-10-11T19:30Z</lastmod></sitemap>
<sitemap><loc>http://www.nasa.gov/sitemap-4.xml</loc><lastmod>2017-10-11T19:30Z</lastmod></sitemap>
</sitemapindex>
```

1.  `process_sitemap()` 从调用 `process_sitemap()` 开始：

```py
def parse_sitemap(s):
  sitemap = process_sitemap(s)
```

1.  这个函数开始调用 `process_sitemap()`，它返回一个包含 `loc`、`lastmod`、`changeFreq` 和 priority 键值对的 Python 字典对象列表：

```py
def process_sitemap(s):
  soup = BeautifulSoup(s, "lxml")
  result = []    for loc in soup.findAll('loc'):
  item = {}
  item['loc'] = loc.text
        item['tag'] = loc.parent.name
        if loc.parent.lastmod is not None:
  item['lastmod'] = loc.parent.lastmod.text
        if loc.parent.changeFreq is not None:
  item['changeFreq'] = loc.parent.changeFreq.text
        if loc.parent.priority is not None:
  item['priority'] = loc.parent.priority.text
        result.append(item)    return result
```

1.  这是通过使用 `BeautifulSoup` 和 `lxml` 解析网站地图来执行的。`loc` 属性始终被设置，如果有相关的 XML 标签，则会设置 `lastmod`、`changeFreq` 和 priority。.tag 属性本身只是指出这个内容是从 `<sitemap>` 标签还是 `<url>` 标签中检索出来的（`<loc>` 标签可以在任何一个标签上）。

`parse_sitemap()` 然后继续逐一处理这些结果：

```py
while sitemap:
  candidate = sitemap.pop()    if is_sub_sitemap(candidate):
  sub_sitemap = get_sitemap(candidate['loc'])
  for i in process_sitemap(sub_sitemap):
  sitemap.append(i)
  else:
  result.append(candidate)
```

1.  检查每个项目。如果它来自网站地图索引文件（URL 以 .xml 结尾且 .tag 是网站地图），那么我们需要读取该 .xml 文件并解析其内容，然后将结果放入我们要处理的项目列表中。在这个例子中，识别出了四个网站地图文件，每个文件都被读取、处理、解析，并且它们的 URL 被添加到结果中。

为了演示一些内容，以下是 sitemap-1.xml 的前几行：

```py
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="//www.nasa.gov/sitemap.xsl"?>
<urlset >
<url><loc>http://www.nasa.gov/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>
<url><loc>http://www.nasa.gov/connect/apps.html</loc><lastmod>2017-08-14T22:15Z</lastmod><changefreq>yearly</changefreq></url>
<url><loc>http://www.nasa.gov/socialmedia</loc><lastmod>2017-09-29T21:47Z</lastmod><changefreq>monthly</changefreq></url>
<url><loc>http://www.nasa.gov/multimedia/imagegallery/iotd.html</loc><lastmod>2017-08-21T22:00Z</lastmod><changefreq>yearly</changefreq></url>
<url><loc>http://www.nasa.gov/archive/archive/about/career/index.html</loc><lastmod>2017-08-04T02:31Z</lastmod><changefreq>yearly</changefreq></url>
```

总的来说，这一个网站地图有 11,006 行，所以大约有 11,000 个 URL！而且总共，正如报道的那样，所有三个网站地图中共有 35,511 个 URL。

# 还有更多...

网站地图文件也可能是经过压缩的，并以 .gz 扩展名结尾。这是因为它可能包含许多 URL，压缩将节省大量空间。虽然我们使用的代码不处理 gzip 网站地图文件，但可以使用 gzip 库中的函数轻松添加这个功能。

Scrapy 还提供了使用网站地图开始爬取的功能。其中之一是 Spider 类的一个特化，SitemapSpider。这个类有智能来解析网站地图，然后开始跟踪 URL。为了演示，脚本`05/03_sitemap_scrapy.py`将从 nasa.gov 的顶级网站地图索引开始爬取：

```py
import scrapy
from scrapy.crawler import CrawlerProcess

class Spider(scrapy.spiders.SitemapSpider):
  name = 'spider'
  sitemap_urls = ['https://www.nasa.gov/sitemap.xml']    def parse(self, response):
  print("Parsing: ", response)   if __name__ == "__main__":
  process = CrawlerProcess({
  'DOWNLOAD_DELAY': 0,
  'LOG_LEVEL': 'DEBUG'
  })
  process.crawl(Spider)
  process.start()
```

运行时，会有大量输出，因为爬虫将开始爬取所有 30000 多个 URL。在输出的早期，您将看到以下输出：

```py
2017-10-11 20:34:27 [scrapy.core.engine] DEBUG: Crawled (200) <GET https://www.nasa.gov/sitemap.xml> (referer: None)
2017-10-11 20:34:27 [scrapy.downloadermiddlewares.redirect] DEBUG: Redirecting (301) to <GET https://www.nasa.gov/sitemap-4.xml> from <GET http://www.nasa.gov/sitemap-4.xml>
2017-10-11 20:34:27 [scrapy.downloadermiddlewares.redirect] DEBUG: Redirecting (301) to <GET https://www.nasa.gov/sitemap-2.xml> from <GET http://www.nasa.gov/sitemap-2.xml>
2017-10-11 20:34:27 [scrapy.downloadermiddlewares.redirect] DEBUG: Redirecting (301) to <GET https://www.nasa.gov/sitemap-3.xml> from <GET http://www.nasa.gov/sitemap-3.xml>
2017-10-11 20:34:27 [scrapy.downloadermiddlewares.redirect] DEBUG: Redirecting (301) to <GET https://www.nasa.gov/sitemap-1.xml> from <GET http://www.nasa.gov/sitemap-1.xml>
2017-10-11 20:34:27 [scrapy.core.engine] DEBUG: Crawled (200) <GET https://www.nasa.gov/sitemap-4.xml> (referer: None)
```

Scrapy 已经找到了所有的网站地图并读取了它们的内容。不久之后，您将开始看到许多重定向和通知，指出正在解析某些页面：

```py
2017-10-11 20:34:30 [scrapy.downloadermiddlewares.redirect] DEBUG: Redirecting (302) to <GET https://www.nasa.gov/image-feature/jpl/pia21629/neptune-from-saturn/> from <GET https://www.nasa.gov/image-feature/jpl/pia21629/neptune-from-saturn>
2017-10-11 20:34:30 [scrapy.downloadermiddlewares.redirect] DEBUG: Redirecting (302) to <GET https://www.nasa.gov/centers/ames/earthscience/members/nasaearthexchange/Ramakrishna_Nemani/> from <GET https://www.nasa.gov/centers/ames/earthscience/members/nasaearthexchang
```

```py
e/Ramakrishna_Nemani>
Parsing: <200 https://www.nasa.gov/exploration/systems/sls/multimedia/sls-hardware-being-moved-on-kamag-transporter.html>
Parsing: <200 https://www.nasa.gov/exploration/systems/sls/M17-057.html>
```

# 带延迟的爬取

快速抓取被认为是一种不良实践。持续不断地访问网站页面可能会消耗 CPU 和带宽，而且强大的网站会识别到您这样做并阻止您的 IP。如果您运气不好，可能会因违反服务条款而收到一封恶意的信！

在爬虫中延迟请求的技术取决于您的爬虫是如何实现的。如果您使用 Scrapy，那么您可以设置一个参数，告诉爬虫在请求之间等待多长时间。在一个简单的爬虫中，只需按顺序处理 URL 的列表，您可以插入一个 thread.sleep 语句。

如果您实施了一个分布式爬虫集群，以分散页面请求的负载，比如使用具有竞争消费者的消息队列，情况可能会变得更加复杂。这可能有许多不同的解决方案，这超出了本文档提供的范围。

# 准备工作

我们将使用带延迟的 Scrapy。示例在`o5/04_scrape_with_delay.py`中。

# 如何做

Scrapy 默认在页面请求之间强加了 0 秒的延迟。也就是说，默认情况下不会在请求之间等待。

1.  这可以使用`DOWNLOAD_DELAY`设置来控制。为了演示，让我们从命令行运行脚本：

```py
05 $ scrapy runspider 04_scrape_with_delay.py -s LOG_LEVEL=WARNING
Parsing: <200 https://blog.scrapinghub.com>
Parsing: <200 https://blog.scrapinghub.com/page/2/>
Parsing: <200 https://blog.scrapinghub.com/page/3/>
Parsing: <200 https://blog.scrapinghub.com/page/4/>
Parsing: &lt;200 https://blog.scrapinghub.com/page/5/>
Parsing: <200 https://blog.scrapinghub.com/page/6/>
Parsing: <200 https://blog.scrapinghub.com/page/7/>
Parsing: <200 https://blog.scrapinghub.com/page/8/>
Parsing: <200 https://blog.scrapinghub.com/page/9/>
Parsing: <200 https://blog.scrapinghub.com/page/10/>
Parsing: <200 https://blog.scrapinghub.com/page/11/>
Total run time: 0:00:07.006148
Michaels-iMac-2:05 michaelheydt$ 
```

这将爬取 blog.scrapinghub.com 上的所有页面，并报告执行爬取的总时间。`LOG_LEVEL=WARNING`会删除大部分日志输出，只会输出打印语句的输出。这使用了默认的页面等待时间为 0，爬取大约需要七秒钟。

1.  页面之间的等待时间可以使用`DOWNLOAD_DELAY`设置。以下在页面请求之间延迟五秒：

```py
05 $ scrapy runspider 04_scrape_with_delay.py -s DOWNLOAD_DELAY=5 -s LOG_LEVEL=WARNING
Parsing: <200 https://blog.scrapinghub.com>
Parsing: <200 https://blog.scrapinghub.com/page/2/>
Parsing: <200 https://blog.scrapinghub.com/page/3/>
Parsing: <200 https://blog.scrapinghub.com/page/4/>
Parsing: <200 https://blog.scrapinghub.com/page/5/>
Parsing: <200 https://blog.scrapinghub.com/page/6/>
Parsing: <200 https://blog.scrapinghub.com/page/7/>
Parsing: <200 https://blog.scrapinghub.com/page/8/>
Parsing: <200 https://blog.scrapinghub.com/page/9/>
Parsing: <200 https://blog.scrapinghub.com/page/10/>
Parsing: <200 https://blog.scrapinghub.com/page/11/>
Total run time: 0:01:01.099267
```

默认情况下，这实际上并不会等待 5 秒。它将等待`DOWNLOAD_DELAY`秒，但是在`DOWNLOAD_DELAY`的 0.5 到 1.5 倍之间有一个随机因素。为什么这样做？这会让您的爬虫看起来“不那么机械化”。您可以通过使用`RANDOMIZED_DOWNLOAD_DELAY=False`设置来关闭这个功能。

# 它是如何工作的

这个爬虫是作为一个 Scrapy 爬虫实现的。类定义从声明爬虫名称和起始 URL 开始：

```py
class Spider(scrapy.Spider):
  name = 'spider'
  start_urls = ['https://blog.scrapinghub.com']
```

解析方法查找 CSS 'div.prev-post > a'，并跟踪这些链接。

爬虫还定义了一个 close 方法，当爬取完成时，Scrapy 会调用这个方法：

```py
def close(spider, reason):
  start_time = spider.crawler.stats.get_value('start_time')
  finish_time = spider.crawler.stats.get_value('finish_time')
  print("Total run time: ", finish_time-start_time)
```

这访问了爬虫的统计对象，检索了爬虫的开始和结束时间，并向用户报告了差异。

# 还有更多...

脚本还定义了在直接使用 Python 执行脚本时的代码：

```py
if __name__ == "__main__":
  process = CrawlerProcess({
  'DOWNLOAD_DELAY': 5,
  'RANDOMIZED_DOWNLOAD_DELAY': False,
  'LOG_LEVEL': 'DEBUG'
  })
  process.crawl(Spider)
  process.start()
```

这是通过创建一个 CrawlerProcess 对象开始的。这个对象可以传递一个表示设置和值的字典，以配置爬取。这默认为五秒的延迟，没有随机化，并且输出级别为 DEBUG。

# 使用可识别的用户代理

如果您违反了服务条款并被网站所有者标记了怎么办？您如何帮助网站所有者联系您，以便他们可以友好地要求您停止对他们认为合理的抓取级别？

为了方便这一点，您可以在请求的 User-Agent 标头中添加有关自己的信息。我们已经在`robots.txt`文件中看到了这样的例子，比如来自 amazon.com。在他们的`robots.txt`中明确声明了一个用于 Google 的用户代理：GoogleBot。

在爬取过程中，您可以在 HTTP 请求的 User-Agent 标头中嵌入自己的信息。为了礼貌起见，您可以输入诸如'MyCompany-MyCrawler（mybot@mycompany.com）'之类的内容。如果远程服务器标记您违规，肯定会捕获这些信息，如果提供了这样的信息，他们可以方便地与您联系，而不仅仅是关闭您的访问。

# 如何做到

根据您使用的工具，设置用户代理会有所不同。最终，它只是确保 User-Agent 标头设置为您指定的字符串。在使用浏览器时，这通常由浏览器设置为标识浏览器和操作系统。但您可以在此标头中放入任何您想要的内容。在使用请求时，这非常简单：

```py
url = 'https://api.github.com/some/endpoint'
headers = {'user-agent': 'MyCompany-MyCrawler (mybot@mycompany.com)'}
r = requests.get(url, headers=headers) 
```

在使用 Scrapy 时，只需配置一个设置即可：

```py
process = CrawlerProcess({
 'USER_AGENT': 'MyCompany-MyCrawler (mybot@mycompany.com)'  }) process.crawl(Spider) process.start()
```

# 它是如何工作的

传出的 HTTP 请求有许多不同的标头。这些确保 User-Agent 标头对目标网站的所有请求都设置为此值。

# 还有更多...

虽然可能将任何内容设置为 User-Agent 标头，但有些 Web 服务器会检查 User-Agent 标头并根据内容做出响应。一个常见的例子是使用标头来识别移动设备以提供移动展示。

但有些网站只允许特定 User-Agent 值访问内容。设置自己的值可能导致 Web 服务器不响应或返回其他错误，比如未经授权。因此，在使用此技术时，请确保检查它是否有效。

# 设置每个域的并发请求数量

一次只爬取一个网址通常效率低下。因此，通常会同时向目标站点发出多个页面请求。通常情况下，远程 Web 服务器可以相当有效地处理多个同时的请求，而在您的端口，您只是在等待每个请求返回数据，因此并发通常对您的爬虫工作效果很好。

但这也是聪明的网站可以识别并标记为可疑活动的模式。而且，您的爬虫端和网站端都有实际限制。发出的并发请求越多，双方都需要更多的内存、CPU、网络连接和网络带宽。这都涉及成本，并且这些值也有实际限制。

因此，通常最好的做法是设置您将同时向任何 Web 服务器发出的请求的数量限制。

# 它是如何工作的

有许多技术可以用来控制并发级别，这个过程通常会相当复杂，需要控制多个请求和执行线程。我们不会在这里讨论如何在线程级别进行操作，只提到了内置在 Scrapy 中的构造。

Scrapy 在其请求中天生是并发的。默认情况下，Scrapy 将最多同时向任何给定域发送八个请求。您可以使用`CONCURRENT_REQUESTS_PER_DOMAIN`设置来更改这一点。以下将该值设置为 1 个并发请求：

```py
process = CrawlerProcess({
 'CONCURRENT_REQUESTS_PER_DOMAIN': 1  }) process.crawl(Spider) process.start()
```

# 使用自动节流

与控制最大并发级别紧密相关的是节流的概念。不同的网站在不同时间对请求的处理能力不同。在响应时间较慢的时期，减少请求的数量是有意义的。这可能是一个繁琐的过程，需要手动监控和调整。

幸运的是，对于我们来说，scrapy 还提供了通过名为`AutoThrottle`的扩展来实现这一点的能力。

# 如何做到

可以使用`AUTOTHROTTLE_TARGET_CONCURRENCY`设置轻松配置 AutoThrottle。

```py
process = CrawlerProcess({
 'AUTOTHROTTLE_TARGET_CONCURRENCY': 3  }) process.crawl(Spider) process.start()
```

# 它是如何工作的

scrapy 跟踪每个请求的延迟。利用这些信息，它可以调整请求之间的延迟，以便在特定域上同时活动的请求不超过`AUTOTHROTTLE_TARGET_CONCURRENCY`，并且请求在任何给定的时间跨度内均匀分布。

# 还有更多...

有很多控制节流的选项。您可以在以下网址上获得它们的概述：[`doc.scrapy.org/en/latest/topics/autothrottle.html?&_ga=2.54316072.1404351387.1507758575-507079265.1505263737#settings.`](https://doc.scrapy.org/en/latest/topics/autothrottle.html?&_ga=2.54316072.1404351387.1507758575-507079265.1505263737#settings)

# 使用 HTTP 缓存进行开发

网络爬虫的开发是一个探索过程，将通过各种细化来迭代检索所需的信息。在开发过程中，您经常会反复访问远程服务器和这些服务器上的相同 URL。这是不礼貌的。幸运的是，scrapy 也通过提供专门设计用于帮助解决这种情况的缓存中间件来拯救您。

# 如何做到这一点

Scrapy 将使用名为 HttpCacheMiddleware 的中间件模块缓存请求。启用它就像将`HTTPCACHE_ENABLED`设置为`True`一样简单：

```py
process = CrawlerProcess({
 'AUTOTHROTTLE_TARGET_CONCURRENCY': 3  }) process.crawl(Spider) process.start()
```

# 它是如何工作的

HTTP 缓存的实现既简单又复杂。Scrapy 提供的`HttpCacheMiddleware`根据您的需求有大量的配置选项。最终，它归结为将每个 URL 及其内容存储在存储器中，并附带缓存过期的持续时间。如果在过期间隔内对 URL 进行第二次请求，则将检索本地副本，而不是进行远程请求。如果时间已经过期，则从 Web 服务器获取内容，存储在缓存中，并设置新的过期时间。

# 还有更多...

有许多配置 scrapy 缓存的选项，包括存储内容的方式（文件系统、DBM 或 LevelDB）、缓存策略以及如何处理来自服务器的 Http 缓存控制指令。要探索这些选项，请查看以下网址：[`doc.scrapy.org/en/latest/topics/downloader-middleware.html?_ga=2.50242598.1404351387.1507758575-507079265.1505263737#dummy-policy-default.`](https://doc.scrapy.org/en/latest/topics/downloader-middleware.html?_ga=2.50242598.1404351387.1507758575-507079265.1505263737#dummy-policy-default.)


# 第六章：爬取挑战和解决方案

在本章中，我们将涵盖：

+   重试失败的页面下载

+   支持页面重定向

+   等待 Selenium 中的内容可用

+   将爬行限制为单个域

+   处理无限滚动页面

+   控制爬行的深度

+   控制爬行的长度

+   处理分页网站

+   处理表单和基于表单的授权

+   处理基本授权

+   通过代理防止被禁止爬取

+   随机化用户代理

+   缓存响应

# 介绍

开发可靠的爬虫从来都不容易，我们需要考虑很多*假设*。如果网站崩溃了怎么办？如果响应返回意外数据怎么办？如果您的 IP 被限制或阻止了怎么办？如果需要身份验证怎么办？虽然我们永远无法预测和涵盖所有*假设*，但我们将讨论一些常见的陷阱、挑战和解决方法。

请注意，其中几个配方需要访问我提供的作为 Docker 容器的网站。它们需要比我们在早期章节中使用的简单静态站点更多的逻辑。因此，您需要使用以下 Docker 命令拉取和运行 Docker 容器：

```py
docker pull mheydt/pywebscrapecookbook
docker run -p 5001:5001 pywebscrapecookbook
```

# 重试失败的页面下载

使用重试中间件，Scrapy 可以轻松处理失败的页面请求。安装后，Scrapy 将在接收以下 HTTP 错误代码时尝试重试：

`[500, 502, 503, 504, 408]`

可以使用以下参数进一步配置该过程：

+   `RETRY_ENABLED`（True/False-默认为 True）

+   `RETRY_TIMES`（在任何错误上重试的次数-默认为 2）

+   `RETRY_HTTP_CODES`（应该重试的 HTTP 错误代码列表-默认为[500, 502, 503, 504, 408]）

# 如何做到

`06/01_scrapy_retry.py`脚本演示了如何配置 Scrapy 进行重试。脚本文件包含了以下 Scrapy 的配置：

```py
process = CrawlerProcess({
  'LOG_LEVEL': 'DEBUG',
  'DOWNLOADER_MIDDLEWARES':
 {  "scrapy.downloadermiddlewares.retry.RetryMiddleware": 500
  },
  'RETRY_ENABLED': True,
  'RETRY_TIMES': 3 }) process.crawl(Spider) process.start()
```

# 它是如何工作的

Scrapy 在运行蜘蛛时会根据指定的重试配置进行重试。在遇到错误时，Scrapy 会在放弃之前最多重试三次。

# 支持页面重定向

Scrapy 中的页面重定向是使用重定向中间件处理的，默认情况下已启用。可以使用以下参数进一步配置该过程：

+   `REDIRECT_ENABLED`：（True/False-默认为 True）

+   `REDIRECT_MAX_TIMES`：（对于任何单个请求要遵循的最大重定向次数-默认为 20）

# 如何做到

`06/02_scrapy_redirects.py`脚本演示了如何配置 Scrapy 来处理重定向。这为任何页面配置了最多两次重定向。运行该脚本会读取 NASA 站点地图并爬取内容。其中包含大量重定向，其中许多是从 HTTP 到 HTTPS 版本的 URL 的重定向。输出会很多，但以下是一些演示输出的行：

```py
Parsing: <200 https://www.nasa.gov/content/earth-expeditions-above/>
['http://www.nasa.gov/content/earth-expeditions-above', 'https://www.nasa.gov/content/earth-expeditions-above']
```

此特定 URL 在重定向后被处理，从 URL 的 HTTP 版本重定向到 HTTPS 版本。该列表定义了涉及重定向的所有 URL。

您还将能够看到输出页面中重定向超过指定级别（2）的位置。以下是一个例子：

```py
2017-10-22 17:55:00 [scrapy.downloadermiddlewares.redirect] DEBUG: Discarding <GET http://www.nasa.gov/topics/journeytomars/news/index.html>: max redirections reached
```

# 它是如何工作的

蜘蛛被定义为以下内容：

```py
class Spider(scrapy.spiders.SitemapSpider):
  name = 'spider'
  sitemap_urls = ['https://www.nasa.gov/sitemap.xml']    def parse(self, response):
  print("Parsing: ", response)
  print (response.request.meta.get('redirect_urls'))
```

这与我们之前基于 NASA 站点地图的爬虫相同，只是增加了一行打印`redirect_urls`。在对`parse`的任何调用中，此元数据将包含到达此页面所发生的所有重定向。

爬行过程使用以下代码进行配置：

```py
process = CrawlerProcess({
  'LOG_LEVEL': 'DEBUG',
  'DOWNLOADER_MIDDLEWARES':
 {  "scrapy.downloadermiddlewares.redirect.RedirectMiddleware": 500
  },
  'REDIRECT_ENABLED': True,
  'REDIRECT_MAX_TIMES': 2 }) 
```

重定向默认已启用，但这将将最大重定向次数设置为 2，而不是默认值 20。

# 等待 Selenium 中的内容可用

动态网页的一个常见问题是，即使整个页面已经加载完成，因此 Selenium 中的`get()`方法已经返回，仍然可能有我们需要稍后访问的内容，因为页面上仍有未完成的 Ajax 请求。这个的一个例子是需要点击一个按钮，但是在加载页面后，直到所有数据都已异步加载到页面后，按钮才被启用。

以以下页面为例：[`the-internet.herokuapp.com/dynamic_loading/2`](http://the-internet.herokuapp.com/dynamic_loading/2)。这个页面加载非常快，然后呈现给我们一个开始按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/08dd65a4-9018-4136-9bb9-0b7f74e17aff.png)屏幕上呈现的开始按钮

按下按钮后，我们会看到一个进度条，持续五秒：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/530d1355-e1cc-4551-ab0f-9374c029b03e.png)等待时的状态栏

当这个完成后，我们会看到 Hello World！

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/d37ade1b-f857-4a5f-a7ce-5157238e9e09.png)页面完全渲染后

现在假设我们想要爬取这个页面，以获取只有在按下按钮并等待后才暴露的内容？我们该怎么做？

# 如何做到这一点

我们可以使用 Selenium 来做到这一点。我们将使用 Selenium 的两个功能。第一个是点击页面元素的能力。第二个是等待直到页面上具有特定 ID 的元素可用。

1.  首先，我们获取按钮并点击它。按钮的 HTML 如下：

```py
<div id='start'>
   <button>Start</button>
</div>
```

1.  当按下按钮并加载完成后，以下 HTML 将被添加到文档中：

```py
<div id='finish'>
   <h4>Hello World!"</h4>
</div>
```

1.  我们将使用 Selenium 驱动程序来查找开始按钮，点击它，然后等待直到`div`中的 ID 为`'finish'`可用。然后我们获取该元素并返回封闭的`<h4>`标签中的文本。

您可以通过运行`06/03_press_and_wait.py`来尝试这个。它的输出将是以下内容：

```py
clicked
Hello World!
```

现在让我们看看它是如何工作的。

# 它是如何工作的

让我们分解一下解释：

1.  我们首先从 Selenium 中导入所需的项目：

```py
from selenium import webdriver
from selenium.webdriver.support import ui
```

1.  现在我们加载驱动程序和页面：

```py
driver = webdriver.PhantomJS() driver.get("http://the-internet.herokuapp.com/dynamic_loading/2")
```

1.  页面加载后，我们可以检索按钮：

```py
button = driver.find_element_by_xpath("//*/div[@id='start']/button")
```

1.  然后我们可以点击按钮：

```py
button.click() print("clicked")
```

1.  接下来我们创建一个`WebDriverWait`对象：

```py
wait = ui.WebDriverWait(driver, 10)
```

1.  有了这个对象，我们可以请求 Selenium 的 UI 等待某些事件。这也设置了最长等待 10 秒。现在使用这个，我们可以等到我们满足一个标准；使用以下 XPath 可以识别一个元素：

```py
wait.until(lambda driver: driver.find_element_by_xpath("//*/div[@id='finish']"))
```

1.  当这完成后，我们可以检索 h4 元素并获取其封闭文本：

```py
finish_element=driver.find_element_by_xpath("//*/div[@id='finish']/h4") print(finish_element.text)
```

# 限制爬行到单个域

我们可以通知 Scrapy 将爬行限制在指定域内的页面。这是一个重要的任务，因为链接可以指向网页的任何地方，我们通常希望控制爬行的方向。Scrapy 使这个任务非常容易。只需要设置爬虫类的`allowed_domains`字段即可。 

# 如何做到这一点

这个示例的代码是`06/04_allowed_domains.py`。您可以使用 Python 解释器运行脚本。它将执行并生成大量输出，但如果您留意一下，您会发现它只处理 nasa.gov 上的页面。

# 它是如何工作的

代码与之前的 NASA 网站爬虫相同，只是我们包括`allowed_domains=['nasa.gov']`：

```py
class Spider(scrapy.spiders.SitemapSpider):
  name = 'spider'
  sitemap_urls = ['https://www.nasa.gov/sitemap.xml']
  allowed_domains=['nasa.gov']    def parse(self, response):
  print("Parsing: ", response) 
```

NASA 网站在其根域内保持相当一致，但偶尔会有指向其他网站的链接，比如 boeing.com 上的内容。这段代码将阻止转移到这些外部网站。

# 处理无限滚动页面

许多网站已经用无限滚动机制取代了“上一页/下一页”分页按钮。这些网站使用这种技术在用户到达页面底部时加载更多数据。因此，通过点击“下一页”链接进行爬行的策略就会崩溃。

虽然这似乎是使用浏览器自动化来模拟滚动的情况，但实际上很容易找出网页的 Ajax 请求，并使用这些请求来爬取，而不是实际页面。让我们以`spidyquotes.herokuapp.com/scroll`为例。

# 准备就绪

在浏览器中打开[`spidyquotes.herokuapp.com/scroll`](http://spidyquotes.herokuapp.com/scroll)。当你滚动到页面底部时，页面将加载更多内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/5aedcf3b-b3dd-4e67-8328-7093d70c2db4.png)要抓取的引用的屏幕截图

页面打开后，进入开发者工具并选择网络面板。然后，滚动到页面底部。您将在网络面板中看到新内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/b8f8c31d-706b-4f11-bab8-901263f7fdfc.png)开发者工具选项的屏幕截图

当我们点击其中一个链接时，我们可以看到以下 JSON：

```py
{
"has_next": true,
"page": 2,
"quotes": [{
"author": {
"goodreads_link": "/author/show/82952.Marilyn_Monroe",
"name": "Marilyn Monroe",
"slug": "Marilyn-Monroe"
},
"tags": ["friends", "heartbreak", "inspirational", "life", "love", "sisters"],
"text": "\u201cThis life is what you make it...."
}, {
"author": {
"goodreads_link": "/author/show/1077326.J_K_Rowling",
"name": "J.K. Rowling",
"slug": "J-K-Rowling"
},
"tags": ["courage", "friends"],
"text": "\u201cIt takes a great deal of bravery to stand up to our enemies, but just as much to stand up to our friends.\u201d"
},
```

这很棒，因为我们只需要不断生成对`/api/quotes?page=x`的请求，增加`x`直到回复文档中存在`has_next`标签。如果没有更多页面，那么这个标签将不在文档中。

# 如何做到这一点

`06/05_scrapy_continuous.py`文件包含一个 Scrapy 代理，它爬取这组页面。使用 Python 解释器运行它，你将看到类似以下的输出（以下是输出的多个摘录）：

```py
<200 http://spidyquotes.herokuapp.com/api/quotes?page=2>
2017-10-29 16:17:37 [scrapy.core.scraper] DEBUG: Scraped from <200 http://spidyquotes.herokuapp.com/api/quotes?page=2>
{'text': "“This life is what you make it. No matter what, you're going to mess up sometimes, it's a universal truth. But the good part is you get to decide how you're going to mess it up. Girls will be your friends - they'll act like it anyway. But just remember, some come, some go. The ones that stay with you through everything - they're your true best friends. Don't let go of them. Also remember, sisters make the best friends in the world. As for lovers, well, they'll come and go too. And baby, I hate to say it, most of them - actually pretty much all of them are going to break your heart, but you can't give up because if you give up, you'll never find your soulmate. You'll never find that half who makes you whole and that goes for everything. Just because you fail once, doesn't mean you're gonna fail at everything. Keep trying, hold on, and always, always, always believe in yourself, because if you don't, then who will, sweetie? So keep your head high, keep your chin up, and most importantly, keep smiling, because life's a beautiful thing and there's so much to smile about.”", 'author': 'Marilyn Monroe', 'tags': ['friends', 'heartbreak', 'inspirational', 'life', 'love', 'sisters']}
2017-10-29 16:17:37 [scrapy.core.scraper] DEBUG: Scraped from <200 http://spidyquotes.herokuapp.com/api/quotes?page=2>
{'text': '“It takes a great deal of bravery to stand up to our enemies, but just as much to stand up to our friends.”', 'author': 'J.K. Rowling', 'tags': ['courage', 'friends']}
2017-10-29 16:17:37 [scrapy.core.scraper] DEBUG: Scraped from <200 http://spidyquotes.herokuapp.com/api/quotes?page=2>
{'text': "“If you can't explain it to a six year old, you don't understand it yourself.”", 'author': 'Albert Einstein', 'tags': ['simplicity', 'understand']}
```

当它到达第 10 页时，它将停止，因为它会看到内容中没有设置下一页标志。

# 它是如何工作的

让我们通过蜘蛛来看看这是如何工作的。蜘蛛从以下开始 URL 的定义开始：

```py
class Spider(scrapy.Spider):
  name = 'spidyquotes'
  quotes_base_url = 'http://spidyquotes.herokuapp.com/api/quotes'
  start_urls = [quotes_base_url]
  download_delay = 1.5
```

然后解析方法打印响应，并将 JSON 解析为数据变量：

```py
  def parse(self, response):
  print(response)
  data = json.loads(response.body)
```

然后它循环遍历 JSON 对象的引用元素中的所有项目。对于每个项目，它将向 Scrapy 引擎产生一个新的 Scrapy 项目：

```py
  for item in data.get('quotes', []):
  yield {
  'text': item.get('text'),
  'author': item.get('author', {}).get('name'),
  'tags': item.get('tags'),
 } 
```

然后它检查数据 JSON 变量是否具有`'has_next'`属性，如果有，它将获取下一页并向 Scrapy 产生一个新的请求来解析下一页：

```py
if data['has_next']:
    next_page = data['page'] + 1
  yield scrapy.Request(self.quotes_base_url + "?page=%s" % next_page)
```

# 还有更多...

也可以使用 Selenium 处理无限滚动页面。以下代码在`06/06_scrape_continuous_twitter.py`中：

```py
from selenium import webdriver
import time

driver = webdriver.PhantomJS()   print("Starting") driver.get("https://twitter.com") scroll_pause_time = 1.5   # Get scroll height last_height = driver.execute_script("return document.body.scrollHeight") while True:
  print(last_height)
  # Scroll down to bottom
  driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")    # Wait to load page
  time.sleep(scroll_pause_time)    # Calculate new scroll height and compare with last scroll height
  new_height = driver.execute_script("return document.body.scrollHeight")
  print(new_height, last_height)    if new_height == last_height:
  break
  last_height = new_height
```

输出将类似于以下内容：

```py
Starting
4882
8139 4882
8139
11630 8139
11630
15055 11630
15055
15055 15055
Process finished with exit code 0
```

这段代码首先从 Twitter 加载页面。调用`.get()`将在页面完全加载时返回。然后检索`scrollHeight`，程序滚动到该高度并等待新内容加载片刻。然后再次检索浏览器的`scrollHeight`，如果与`last_height`不同，它将循环并继续处理。如果与`last_height`相同，则没有加载新内容，然后您可以继续检索已完成页面的 HTML。

# 控制爬取的深度

可以使用 Scrapy 的`DepthMiddleware`中间件来控制爬取的深度。深度中间件限制了 Scrapy 从任何给定链接获取的跟随数量。这个选项对于控制你深入到特定爬取中有多有用。这也用于防止爬取过长，并且在你知道你要爬取的内容位于从爬取开始的页面的一定数量的分离度内时非常有用。

# 如何做到这一点

深度控制中间件默认安装在中间件管道中。深度限制的示例包含在`06/06_limit_depth.py`脚本中。该脚本爬取源代码提供的端口 8080 上的静态站点，并允许您配置深度限制。该站点包括三个级别：0、1 和 2，并且每个级别有三个页面。文件名为`CrawlDepth<level><pagenumber>.html`。每个级别的第 1 页链接到同一级别的其他两页，以及下一级别的第 1 页。到达第 2 级的链接结束。这种结构非常适合检查 Scrapy 中如何处理深度处理。

# 它是如何工作的

深度限制可以通过设置`DEPTH_LIMIT`参数来执行：

```py
process = CrawlerProcess({
    'LOG_LEVEL': 'CRITICAL',
    'DEPTH_LIMIT': 2,
    'DEPT_STATS': True })
```

深度限制为 1 意味着我们只会爬取一层，这意味着它将处理`start_urls`中指定的 URL，然后处理这些页面中找到的任何 URL。使用`DEPTH_LIMIT`我们得到以下输出：

```py
Parsing: <200 http://localhost:8080/CrawlDepth0-1.html>
Requesting crawl of: http://localhost:8080/CrawlDepth0-2.html
Requesting crawl of: http://localhost:8080/Depth1/CrawlDepth1-1.html
Parsing: <200 http://localhost:8080/Depth1/CrawlDepth1-1.html>
Requesting crawl of: http://localhost:8080/Depth1/CrawlDepth1-2.html
Requesting crawl of: http://localhost:8080/Depth1/depth1/CrawlDepth1-2.html
Requesting crawl of: http://localhost:8080/Depth1/depth2/CrawlDepth2-1.html
Parsing: <200 http://localhost:8080/CrawlDepth0-2.html>
Requesting crawl of: http://localhost:8080/CrawlDepth0-3.html
<scrapy.statscollectors.MemoryStatsCollector object at 0x109f754e0>
Crawled: ['http://localhost:8080/CrawlDepth0-1.html', 'http://localhost:8080/Depth1/CrawlDepth1-1.html', 'http://localhost:8080/CrawlDepth0-2.html']
Requested: ['http://localhost:8080/CrawlDepth0-2.html', 'http://localhost:8080/Depth1/CrawlDepth1-1.html', 'http://localhost:8080/Depth1/CrawlDepth1-2.html', 'http://localhost:8080/Depth1/depth1/CrawlDepth1-2.html', 'http://localhost:8080/Depth1/depth2/CrawlDepth2-1.html', 'http://localhost:8080/CrawlDepth0-3.html']
```

爬取从`CrawlDepth0-1.html`开始。该页面有两行，一行到`CrawlDepth0-2.html`，一行到`CrawlDepth1-1.html`。然后请求解析它们。考虑到起始页面在深度 0，这些页面在深度 1，是我们深度的限制。因此，我们将看到这两个页面被解析。但是，请注意，这两个页面的所有链接，虽然请求解析，但由于它们在深度 2，超出了指定的限制，因此被 Scrapy 忽略。

现在将深度限制更改为 2：

```py
process = CrawlerProcess({
  'LOG_LEVEL': 'CRITICAL',
  'DEPTH_LIMIT': 2,
  'DEPT_STATS': True })
```

然后输出变成如下：

```py
Parsing: <200 http://localhost:8080/CrawlDepth0-1.html>
Requesting crawl of: http://localhost:8080/CrawlDepth0-2.html
Requesting crawl of: http://localhost:8080/Depth1/CrawlDepth1-1.html
Parsing: <200 http://localhost:8080/Depth1/CrawlDepth1-1.html>
Requesting crawl of: http://localhost:8080/Depth1/CrawlDepth1-2.html
Requesting crawl of: http://localhost:8080/Depth1/depth1/CrawlDepth1-2.html
Requesting crawl of: http://localhost:8080/Depth1/depth2/CrawlDepth2-1.html
Parsing: <200 http://localhost:8080/CrawlDepth0-2.html>
Requesting crawl of: http://localhost:8080/CrawlDepth0-3.html
Parsing: <200 http://localhost:8080/Depth1/depth2/CrawlDepth2-1.html>
Parsing: <200 http://localhost:8080/CrawlDepth0-3.html>
Parsing: <200 http://localhost:8080/Depth1/CrawlDepth1-2.html>
Requesting crawl of: http://localhost:8080/Depth1/CrawlDepth1-3.html
<scrapy.statscollectors.MemoryStatsCollector object at 0x10d3d44e0>
Crawled: ['http://localhost:8080/CrawlDepth0-1.html', 'http://localhost:8080/Depth1/CrawlDepth1-1.html', 'http://localhost:8080/CrawlDepth0-2.html', 'http://localhost:8080/Depth1/depth2/CrawlDepth2-1.html', 'http://localhost:8080/CrawlDepth0-3.html', 'http://localhost:8080/Depth1/CrawlDepth1-2.html']
Requested: ['http://localhost:8080/CrawlDepth0-2.html', 'http://localhost:8080/Depth1/CrawlDepth1-1.html', 'http://localhost:8080/Depth1/CrawlDepth1-2.html', 'http://localhost:8080/Depth1/depth1/CrawlDepth1-2.html', 'http://localhost:8080/Depth1/depth2/CrawlDepth2-1.html', 'http://localhost:8080/CrawlDepth0-3.html', 'http://localhost:8080/Depth1/CrawlDepth1-3.html']
```

请注意，之前被忽略的三个页面，当`DEPTH_LIMIT`设置为 1 时，现在被解析了。现在，这个深度下找到的链接，比如`CrawlDepth1-3.html`页面的链接，现在被忽略了，因为它们的深度超过了 2。

# 控制爬取的长度

爬取的长度，即可以解析的页面数量，可以通过`CLOSESPIDER_PAGECOUNT`设置来控制。

# 如何操作

我们将使用`06/07_limit_length.py`中的脚本。该脚本和爬虫与 NASA 站点地图爬虫相同，只是增加了以下配置来限制解析的页面数量为 5：

```py
if __name__ == "__main__":
  process = CrawlerProcess({
  'LOG_LEVEL': 'INFO',
  'CLOSESPIDER_PAGECOUNT': 5
  })
  process.crawl(Spider)
  process.start()
```

当运行时，将生成以下输出（在日志输出中交错）：

```py
<200 https://www.nasa.gov/exploration/systems/sls/multimedia/sls-hardware-being-moved-on-kamag-transporter.html>
<200 https://www.nasa.gov/exploration/systems/sls/M17-057.html>
<200 https://www.nasa.gov/press-release/nasa-awards-contract-for-center-protective-services-for-glenn-research-center/>
<200 https://www.nasa.gov/centers/marshall/news/news/icymi1708025/>
<200 https://www.nasa.gov/content/oracles-completed-suit-case-flight-series-to-ascension-island/>
<200 https://www.nasa.gov/feature/goddard/2017/asteroid-sample-return-mission-successfully-adjusts-course/>
<200 https://www.nasa.gov/image-feature/jpl/pia21754/juling-crater/>
```

# 工作原理

请注意，我们将页面限制设置为 5，但实际示例解析了 7 页。`CLOSESPIDER_PAGECOUNT`的值应被视为 Scrapy 将至少执行的值，但可能会略微超出。

# 处理分页网站

分页将大量内容分成多个页面。通常，这些页面有一个供用户点击的上一页/下一页链接。这些链接通常可以通过 XPath 或其他方式找到，然后跟随以到达下一页（或上一页）。让我们来看看如何使用 Scrapy 遍历页面。我们将看一个假设的例子，爬取自动互联网搜索结果。这些技术直接适用于许多具有搜索功能的商业网站，并且很容易修改以适应这些情况。

# 准备工作

我们将演示如何处理分页，示例将从提供的容器网站中爬取一组页面。该网站模拟了五个页面，每个页面上都有上一页和下一页的链接，以及每个页面中的一些嵌入数据，我们将提取这些数据。

这个集合的第一页可以在`http://localhost:5001/pagination/page1.html`中看到。以下图片显示了这个页面的打开情况，我们正在检查下一页按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/2c9af8d6-9b76-47e9-965e-1875830119d4.png)检查下一页按钮

页面有两个感兴趣的部分。第一个是下一页按钮的链接。这个链接通常有一个类来标识链接作为下一页的链接。我们可以使用这个信息来找到这个链接。在这种情况下，我们可以使用以下 XPath 找到它：

```py
//*/a[@class='next']
```

第二个感兴趣的部分实际上是从页面中检索我们想要的数据。在这些页面上，这是由具有`class="data"`属性的`<div>`标签标识的。这些页面只有一个数据项，但在这个搜索结果页面爬取的示例中，我们将提取多个项目。

现在让我们实际运行这些页面的爬虫。

# 如何操作

有一个名为`06/08_scrapy_pagination.py`的脚本。用 Python 运行此脚本，Scrapy 将输出大量内容，其中大部分将是标准的 Scrapy 调试输出。但是，在这些输出中，您将看到我们提取了所有五个页面上的数据项：

```py
Page 1 Data
Page 2 Data
Page 3 Data
Page 4 Data
Page 5 Data
```

# 工作原理

代码从定义`CrawlSpider`和起始 URL 开始：

```py
class PaginatedSearchResultsSpider(CrawlSpider):
    name = "paginationscraper"
  start_urls = [
"http://localhost:5001/pagination/page1.html"
  ]
```

然后定义了规则字段，它告诉 Scrapy 如何解析每个页面以查找链接。此代码使用前面讨论的 XPath 来查找页面中的下一个链接。Scrapy 将使用此规则在每个页面上查找下一个要处理的页面，并将该请求排队等待处理。对于找到的每个页面，回调参数告诉 Scrapy 调用哪个方法进行处理，在本例中是`parse_result_page`：

```py
rules = (
# Extract links for next pages
  Rule(LinkExtractor(allow=(),
restrict_xpaths=("//*/a[@class='next']")),
callback='parse_result_page', follow=True),
)
```

声明了一个名为`all_items`的单个列表变量来保存我们找到的所有项目：

```py
all_items = []
```

然后定义了`parse_start_url`方法。Scrapy 将调用此方法来解析爬行中的初始 URL。该函数简单地将处理推迟到`parse_result_page`：

```py
def parse_start_url(self, response):
  return self.parse_result_page(response)
```

然后，`parse_result_page`方法使用 XPath 来查找`<div class="data">`标签中`<h1>`标签内的文本。然后将该文本附加到`all_items`列表中：

```py
def parse_result_page(self, response):
    data_items = response.xpath("//*/div[@class='data']/h1/text()")
for data_item in data_items:
 self.all_items.append(data_item.root)
```

爬行完成后，将调用`closed()`方法并写出`all_items`字段的内容：

```py
def closed(self, reason):
  for i in self.all_items:
  print(i) 
```

使用 Python 作为脚本运行爬虫，如下所示：

```py
if __name__ == "__main__":
  process = CrawlerProcess({
  'LOG_LEVEL': 'DEBUG',
  'CLOSESPIDER_PAGECOUNT': 10   })
  process.crawl(ImdbSearchResultsSpider)
  process.start()
```

请注意，`CLOSESPIDER_PAGECOUNT`属性被设置为`10`。这超过了该网站上的页面数量，但在许多（或大多数）情况下，搜索结果可能会有数千个页面。在适当数量的页面后停止是一个很好的做法。这是爬虫的良好行为，因为在前几页之后，与您的搜索相关的项目的相关性急剧下降，因此在前几页之后继续爬行会大大减少回报，通常最好在几页后停止。

# 还有更多...

正如在本教程开始时提到的，这很容易修改为在各种内容网站上进行各种自动搜索。这种做法可能会推动可接受使用的极限，因此这里进行了泛化。但是，要获取更多实际示例，请访问我的博客：`www.smac.io`。

# 处理表单和基于表单的授权

我们经常需要在爬取网站内容之前登录网站。这通常是通过一个表单完成的，我们在其中输入用户名和密码，按*Enter*，然后获得以前隐藏的内容的访问权限。这种类型的表单认证通常称为 cookie 授权，因为当我们授权时，服务器会创建一个 cookie，用于验证您是否已登录。Scrapy 尊重这些 cookie，所以我们所需要做的就是在爬行过程中自动化表单。

# 准备工作

我们将在容器网站的页面上爬行以下 URL：`http://localhost:5001/home/secured`。在此页面上，以及从该页面链接出去的页面，有我们想要抓取的内容。但是，此页面被登录阻止。在浏览器中打开页面时，我们会看到以下登录表单，我们可以在其中输入`darkhelmet`作为用户名，`vespa`作为密码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/518cef3e-91c8-47a3-b978-020504dcc4ca.png)输入用户名和密码凭证

按下*Enter*后，我们将得到验证，并被带到最初想要的页面。

那里没有太多的内容，但这条消息足以验证我们已经登录，我们的爬虫也知道这一点。

# 如何操作

我们按照以下步骤进行：

1.  如果您检查登录页面的 HTML，您会注意到以下表单代码：

```py
<form action="/Account/Login" method="post"><div>
 <label for="Username">Username</label>
 <input type="text" id="Username" name="Username" value="" />
 <span class="field-validation-valid" data-valmsg-for="Username" data-valmsg-replace="true"></span></div>
<div>
 <label for="Password">Password</label>
 <input type="password" id="Password" name="Password" />
 <span class="field-validation-valid" data-valmsg-for="Password" data-valmsg-replace="true"></span>
 </div> 
 <input type="hidden" name="returnUrl" />
<input name="submit" type="submit" value="Login"/>
 <input name="__RequestVerificationToken" type="hidden" value="CfDJ8CqzjGWzUMJKkKCmxuBIgZf3UkeXZnVKBwRV_Wu4qUkprH8b_2jno5-1SGSNjFqlFgLie84xI2ZBkhHDzwgUXpz6bbBwER0v_-fP5iTITiZi2VfyXzLD_beXUp5cgjCS5AtkIayWThJSI36InzBqj2A" /></form>
```

1.  要使 Scrapy 中的表单处理器工作，我们需要该表单中用户名和密码字段的 ID。它们分别是`Username`和`Password`。现在我们可以使用这些信息创建一个蜘蛛。这个蜘蛛在脚本文件`06/09_forms_auth.py`中。蜘蛛定义以以下内容开始：

```py
class Spider(scrapy.Spider):
  name = 'spider'
  start_urls = ['http://localhost:5001/home/secured']
  login_user = 'darkhelmet'
  login_pass = 'vespa'
```

1.  我们在类中定义了两个字段`login_user`和`login_pass`，用于保存我们要使用的用户名。爬行也将从指定的 URL 开始。

1.  然后更改`parse`方法以检查页面是否包含登录表单。这是通过使用 XPath 来查看页面是否有一个类型为密码的输入表单，并且具有`id`为`Password`的方式来完成的：

```py
def parse(self, response):
  print("Parsing: ", response)    count_of_password_fields = int(float(response.xpath("count(//*/input[@type='password' and @id='Password'])").extract()[0]))
  if count_of_password_fields > 0:
  print("Got a password page") 
```

1.  如果找到了该字段，我们将返回一个`FormRequest`给 Scrapy，使用它的`from_response`方法生成：

```py
return scrapy.FormRequest.from_response(
 response,
  formdata={'Username': self.login_user, 'Password': self.login_pass},
  callback=self.after_login)
```

1.  这个函数接收响应，然后是一个指定需要插入数据的字段的 ID 的字典，以及这些值。然后定义一个回调函数，在 Scrapy 执行这个 FormRequest 后执行，并将生成的表单内容传递给它：

```py
def after_login(self, response):
  if "This page is secured" in str(response.body):
  print("You have logged in ok!")
```

1.  这个回调函数只是寻找单词`This page is secured`，只有在登录成功时才会返回。当成功运行时，我们将从我们的爬虫的打印语句中看到以下输出：

```py
Parsing: <200 http://localhost:5001/account/login?ReturnUrl=%2Fhome%2Fsecured>
Got a password page
You have logged in ok!
```

# 它是如何工作的

当您创建一个`FormRequest`时，您正在指示 Scrapy 代表您的进程构造一个表单 POST 请求，使用指定字典中的数据作为 POST 请求中的表单参数。它构造这个请求并将其发送到服务器。在收到 POST 的答复后，它调用指定的回调函数。

# 还有更多...

这种技术在许多其他类型的表单输入中也很有用，不仅仅是登录表单。这可以用于自动化，然后执行任何类型的 HTML 表单请求，比如下订单，或者用于执行搜索操作的表单。

# 处理基本授权

一些网站使用一种称为*基本授权*的授权形式。这在其他授权方式（如 cookie 授权或 OAuth）出现之前很流行。它也常见于企业内部网络和一些 Web API。在基本授权中，一个头部被添加到 HTTP 请求中。这个头部，`Authorization`，传递了 Basic 字符串，然后是值`<username>:<password>`的 base64 编码。所以在 darkhelmet 的情况下，这个头部会如下所示：

```py
Authorization: Basic ZGFya2hlbG1ldDp2ZXNwYQ==, with ZGFya2hlbG1ldDp2ZXNwYQ== being darkhelmet:vespa base 64 encoded.
```

请注意，这并不比以明文发送更安全（尽管通过 HTTPS 执行时是安全的）。然而，大部分情况下，它已经被更健壮的授权表单所取代，甚至 cookie 授权允许更复杂的功能，比如声明：

# 如何做到

在 Scrapy 中支持基本授权是很简单的。要使其对爬虫和爬取的特定网站起作用，只需在您的爬虫中定义`http_user`，`http_pass`和`name`字段。以下是示例：

```py
class SomeIntranetSiteSpider(CrawlSpider):
    http_user = 'someuser'
    http_pass = 'somepass'
    name = 'intranet.example.com'
    # .. rest of the spider code omitted ...
```

# 它是如何工作的

当爬虫爬取由名称指定的网站上的任何页面时，它将使用`http_user`和`http_pass`的值来构造适当的标头。

# 还有更多...

请注意，这个任务是由 Scrapy 的`HttpAuthMiddleware`模块执行的。有关基本授权的更多信息也可以在[`developer.mozilla.org/en-US/docs/Web/HTTP/Authentication`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication)上找到。

# 通过代理来防止被屏蔽

有时候您可能会因为被识别为爬虫而被屏蔽，有时候是因为网站管理员看到来自统一 IP 的爬取请求，然后他们会简单地屏蔽对该 IP 的访问。

为了帮助防止这个问题，可以在 Scrapy 中使用代理随机化中间件。存在一个名为`scrapy-proxies`的库，它实现了代理随机化功能。

# 准备工作

您可以从 GitHub 上获取`scrapy-proxies`，网址为[`github.com/aivarsk/scrapy-proxies`](https://github.com/aivarsk/scrapy-proxies)，或者使用`pip install scrapy_proxies`进行安装。

# 如何做到

使用`scrapy-proxies`是通过配置完成的。首先要配置`DOWNLOADER_MIDDLEWARES`，并确保安装了`RetryMiddleware`，`RandomProxy`和`HttpProxyMiddleware`。以下是一个典型的配置：

```py
# Retry many times since proxies often fail
RETRY_TIMES = 10
# Retry on most error codes since proxies fail for different reasons
RETRY_HTTP_CODES = [500, 503, 504, 400, 403, 404, 408]

DOWNLOADER_MIDDLEWARES = {
 'scrapy.downloadermiddlewares.retry.RetryMiddleware': 90,
 'scrapy_proxies.RandomProxy': 100,
 'scrapy.downloadermiddlewares.httpproxy.HttpProxyMiddleware': 110,
}
```

`PROXY_LIST`设置被配置为指向一个包含代理列表的文件：

```py
PROXY_LIST = '/path/to/proxy/list.txt'
```

然后，我们需要让 Scrapy 知道`PROXY_MODE`：

```py
# Proxy mode
# 0 = Every requests have different proxy
# 1 = Take only one proxy from the list and assign it to every requests
# 2 = Put a custom proxy to use in the settings
PROXY_MODE = 0
```

如果`PROXY_MODE`是`2`，那么您必须指定一个`CUSTOM_PROXY`：

```py
CUSTOM_PROXY = "http://host1:port"
```

# 它是如何工作的

这个配置基本上告诉 Scrapy，如果对页面的请求失败，并且每个 URL 最多重试`RETRY_TIMES`次中的任何一个`RETRY_HTTP_CODES`，则使用`PROXY_LIST`指定的文件中的代理，并使用`PROXY_MODE`定义的模式。通过这种方式，您可以让 Scrapy 退回到任意数量的代理服务器，以从不同的 IP 地址和/或端口重试请求。

# 随机化用户代理

您使用的用户代理可能会影响爬虫的成功。一些网站将直接拒绝为特定的用户代理提供内容。这可能是因为用户代理被识别为被禁止的爬虫，或者用户代理是不受支持的浏览器（即 Internet Explorer 6）的用户代理。

对爬虫的控制另一个原因是，根据指定的用户代理，内容可能会在网页服务器上以不同的方式呈现。目前移动网站通常会这样做，但也可以用于桌面，比如为旧版浏览器提供更简单的内容。

因此，将用户代理设置为默认值以外的其他值可能是有用的。Scrapy 默认使用名为`scrapybot`的用户代理。可以通过使用`BOT_NAME`参数进行配置。如果使用 Scrapy 项目，Scrapy 将把代理设置为您的项目名称。

对于更复杂的方案，有两个常用的扩展可以使用：`scrapy-fake-agent`和`scrapy-random-useragent`。

# 如何做到这一点

我们按照以下步骤进行操作：

1.  `scrapy-fake-useragent`可在 GitHub 上找到，网址为[`github.com/alecxe/scrapy-fake-useragent`](https://github.com/alecxe/scrapy-fake-useragent)，而`scrapy-random-useragent`可在[`github.com/cnu/scrapy-random-useragent`](https://github.com/cnu/scrapy-random-useragent)找到。您可以使用`pip install scrapy-fake-agent`和/或`pip install scrapy-random-useragent`来包含它们。

1.  `scrapy-random-useragent`将从文件中为每个请求选择一个随机用户代理。它配置在两个设置中：

```py
DOWNLOADER_MIDDLEWARES = {
    'scrapy.contrib.downloadermiddleware.useragent.UserAgentMiddleware': None,
    'random_useragent.RandomUserAgentMiddleware': 400
}
```

1.  这将禁用现有的`UserAgentMiddleware`，并用`RandomUserAgentMiddleware`中提供的实现来替换它。然后，您需要配置一个包含用户代理名称列表的文件的引用：

```py
USER_AGENT_LIST = "/path/to/useragents.txt"
```

1.  配置完成后，每个请求将使用文件中的随机用户代理。

1.  `scrapy-fake-useragent`使用了不同的模型。它从在线数据库中检索用户代理，该数据库跟踪使用最普遍的用户代理。配置 Scrapy 以使用它的设置如下：

```py
DOWNLOADER_MIDDLEWARES = {
    'scrapy.downloadermiddlewares.useragent.UserAgentMiddleware': None,
    'scrapy_fake_useragent.middleware.RandomUserAgentMiddleware': 400,
}
```

1.  它还具有设置使用的用户代理类型的能力，例如移动或桌面，以强制选择这两个类别中的用户代理。这是使用`RANDOM_UA_TYPE`设置执行的，默认为随机。

1.  如果使用`scrapy-fake-useragent`与任何代理中间件，那么您可能希望对每个代理进行随机化。这可以通过将`RANDOM_UA_PER_PROXY`设置为 True 来实现。此外，您还需要将`RandomUserAgentMiddleware`的优先级设置为大于`scrapy-proxies`，以便在处理之前设置代理。

# 缓存响应

Scrapy 具有缓存 HTTP 请求的能力。如果页面已经被访问过，这可以大大减少爬取时间。通过启用缓存，Scrapy 将存储每个请求和响应。

# 如何做到这一点

`06/10_file_cache.py`脚本中有一个可用的示例。在 Scrapy 中，默认情况下禁用了缓存中间件。要启用此缓存，将`HTTPCACHE_ENABLED`设置为`True`，将`HTTPCACHE_DIR`设置为文件系统上的一个目录（使用相对路径将在项目的数据文件夹中创建目录）。为了演示，此脚本运行了 NASA 网站的爬取，并缓存了内容。它的配置如下：

```py
if __name__ == "__main__":
  process = CrawlerProcess({
  'LOG_LEVEL': 'CRITICAL',
  'CLOSESPIDER_PAGECOUNT': 50,
  'HTTPCACHE_ENABLED': True,
  'HTTPCACHE_DIR': "."
  })
  process.crawl(Spider)
  process.start()
```

我们要求 Scrapy 使用文件进行缓存，并在当前文件夹中创建一个子目录。我们还指示它将爬取限制在大约 500 页。运行此操作时，爬取将大约需要一分钟（取决于您的互联网速度），并且大约会有 500 行的输出。

第一次执行后，您会发现您的目录中现在有一个`.scrapy`文件夹，其中包含缓存数据。 结构将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-web-scp-cb/img/5c6f662d-595c-46d0-95f7-c118ffe6afc4.png)

再次运行脚本只需要几秒钟，将产生相同的输出/报告已解析的页面，只是这次内容将来自缓存而不是 HTTP 请求。

# 还有更多...

在 Scrapy 中有许多缓存的配置和选项。默认情况下，由`HTTPCACHE_EXPIRATION_SECS`指定的缓存过期时间设置为 0。 0 表示缓存项永远不会过期，因此一旦写入，Scrapy 将永远不会通过 HTTP 再次请求该项。实际上，您可能希望将其设置为某个会过期的值。

文件存储仅是缓存的选项之一。通过将`HTTPCACHE_STORAGE`设置为`scrapy.extensions.httpcache.DbmCacheStorage`或`scrapy.extensions.httpcache.LeveldbCacheStorage`，也可以将项目缓存在 DMB 和 LevelDB 中。如果您愿意，还可以编写自己的代码，将页面内容存储在另一种类型的数据库或云存储中。

最后，我们来到缓存策略。Scrapy 自带两种内置策略：Dummy（默认）和 RFC2616。这可以通过将`HTTPCACHE_POLICY`设置更改为`scrapy.extensions.httpcache.DummyPolicy`或`scrapy.extensions.httpcache.RFC2616Policy`来设置。

RFC2616 策略通过以下操作启用 HTTP 缓存控制意识：

+   不要尝试存储设置了 no-store 缓存控制指令的响应/请求

+   如果设置了 no-cache 缓存控制指令，即使是新鲜的响应，也不要从缓存中提供响应

+   从 max-age 缓存控制指令计算新鲜度生存期

+   从 Expires 响应标头计算新鲜度生存期

+   从 Last-Modified 响应标头计算新鲜度生存期（Firefox 使用的启发式）

+   从 Age 响应标头计算当前年龄

+   从日期标头计算当前年龄

+   根据 Last-Modified 响应标头重新验证陈旧的响应

+   根据 ETag 响应标头重新验证陈旧的响应

+   为任何接收到的响应设置日期标头

+   支持请求中的 max-stale 缓存控制指令
