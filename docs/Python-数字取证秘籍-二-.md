# Python 数字取证秘籍（二）

> 原文：[`zh.annas-archive.org/md5/941c711b36df2129e5f7d215d3712f03`](https://zh.annas-archive.org/md5/941c711b36df2129e5f7d215d3712f03)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：提取嵌入式元数据配方

本章涵盖以下配方：

+   提取音频和视频元数据

+   大局观

+   挖掘 PDF 元数据

+   审查可执行文件元数据

+   阅读办公文档元数据

+   将我们的元数据提取器与 EnCase 集成

# 介绍

当调查仅涉及少数感兴趣的文件时，提取有关文件的每一条可用信息至关重要。经常被忽视的嵌入式元数据可以为我们提供巩固给定文件证据价值的关键信息。无论是从 Microsoft Office 文件中收集作者信息，从图片中映射 GPS 坐标，还是从可执行文件中提取编译信息，我们都可以更多地了解我们正在调查的文件。在本章中，我们将开发脚本来检查这些文件格式以及其他文件格式，以提取我们审查的关键信息。我们将说明如何将这些配方与流行的取证套件 EnCase 集成，并将它们添加到您的调查工作流程中。

特别是，我们将开发突出以下内容的代码：

+   解析音频和视频格式的 ID3 和 QuickTime 格式的元数据

+   揭示嵌入在图像中的 GPS 坐标

+   从 PDF 文件中识别作者和谱系信息

+   从 Windows 可执行文件中提取嵌入的名称、编译日期和其他属性的信息

+   报告 Microsoft Office 文件的创建和来源

+   从 EnCase 启动 Python 脚本

访问[www.packtpub.com/books/content/support](http://www.packtpub.com/books/content/support)下载本章的代码包。

# 提取音频和视频元数据

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

音频和视频文件是常见的文件格式，它们使用嵌入式元数据。例如，您喜欢的媒体播放器使用此信息来显示您导入的内容的艺术家、专辑和曲目名称信息。尽管大多数信息是标准的并专注于向听众提供信息，但我们有时会在文件的这个领域找到重要的细节。我们从提取音频和视频文件的常见属性开始探索嵌入式元数据。

# 入门

此配方需要安装第三方库`mutagen`。此脚本中使用的所有其他库都包含在 Python 的标准库中。此库允许我们从音频和视频文件中提取元数据。可以使用`pip`安装此库：

```py
pip install mutagen==1.38
```

要了解有关`mutagen`库的更多信息，请访问[`mutagen.readthedocs.io/en/latest`](https://mutagen.readthedocs.io/en/latest)。

# 如何做...

在这个脚本中，我们执行以下步骤：

1.  识别输入文件类型。

1.  从文件类型处理器中提取嵌入式元数据。

# 它是如何工作的...

要从示例 MP3 或 MP4 文件中提取信息，我们首先导入此配方所需的三个库：`argparse`、`json`和`mutagen`。`json`库允许我们加载稍后在此配方中使用的 QuickTime MP4 元数据格式的定义。

```py
from __future__ import print_function
import argparse
import json
import mutagen
```

此配方的命令行处理程序接受一个位置参数`AV_FILE`，表示要处理的 MP3 或 MP4 文件的路径。在解析用户提供的参数之后，我们使用`mutagen.File（）`方法打开文件的句柄。根据输入文件的扩展名，我们将此句柄发送到适当的函数：`handle_id3（）`或`handle_mp4（）`。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("AV_FILE", help="File to extract metadata from")
    args = parser.parse_args()
    av_file = mutagen.File(args.AV_FILE)

    file_ext = args.AV_FILE.rsplit('.', 1)[-1]
    if file_ext.lower() == 'mp3':
        handle_id3(av_file)
    elif file_ext.lower() == 'mp4':
        handle_mp4(av_file)
```

`handle_id3（）`函数负责从 MP3 文件中提取元数据。MP3 格式使用 ID3 标准来存储其元数据。在我们的 ID3 解析函数中，我们首先创建一个名为`id3_frames`的字典，将 ID3 字段（在原始文件中表示）映射到人类可读的字符串。我们可以向此定义添加更多字段，以扩展我们提取的信息。在提取嵌入式元数据之前，我们将适当的列标题打印到控制台。

```py
def handle_id3(id3_file):
    # Definitions from http://id3.org/id3v2.4.0-frames
    id3_frames = {
        'TIT2': 'Title', 'TPE1': 'Artist', 'TALB': 'Album',
        'TXXX': 'Custom', 'TCON': 'Content Type', 'TDRL': 'Date released',
        'COMM': 'Comments', 'TDRC': 'Recording Date'}
    print("{:15} | {:15} | {:38} | {}".format("Frame", "Description",
                                              "Text", "Value"))
    print("-" * 85)
```

接下来，我们使用循环提取每个`id3`帧的名称和各种值。我们查询帧的名称以从`id3_frames`字典中提取其人类可读版本。此外，从每个帧中，我们使用`getattr()`方法提取描述、文本和值（如果存在）。最后，我们将管道分隔的文本打印到控制台进行审查。这样处理了 MP3 文件，现在让我们转到 MP4 文件。

```py
    for frames in id3_file.tags.values():
        frame_name = id3_frames.get(frames.FrameID, frames.FrameID)
        desc = getattr(frames, 'desc', "N/A")
        text = getattr(frames, 'text', ["N/A"])[0]
        value = getattr(frames, 'value', "N/A")
        if "date" in frame_name.lower():
            text = str(text)

        print("{:15} | {:15} | {:38} | {}".format(
            frame_name, desc, text, value))
```

`handle_mp4()`函数负责处理 MP4 文件，并且遵循与之前函数类似的工作流程。我们首先在一个名为`qt_tag`的字典中设置元数据映射，使用版权符号（`u"\u00A9"`）的 Unicode 值作为字段名称的前置字符。这个映射字典被设计成标签名称是键，人类可读的字符串是值。然后，我们使用`json.load()`方法导入了一个大型的媒体类型定义列表（喜剧、播客、乡村等）。通过将 JSON 数据存储到`genre_ids`变量中，这种情况下，我们有一个包含不同类型的键值对的字典，其中键是整数，值是不同的类型。这些定义来自[`www.sno.phy.queensu.ca/~phil/exiftool/TagNames/QuickTime.html#GenreID`](http://www.sno.phy.queensu.ca/~phil/exiftool/TagNames/QuickTime.html#GenreID)。

```py
def handle_mp4(mp4_file):
    cp_sym = u"\u00A9"
    qt_tag = {
        cp_sym + 'nam': 'Title', cp_sym + 'art': 'Artist',
        cp_sym + 'alb': 'Album', cp_sym + 'gen': 'Genre',
        'cpil': 'Compilation', cp_sym + 'day': 'Creation Date',
        'cnID': 'Apple Store Content ID', 'atID': 'Album Title ID',
        'plID': 'Playlist ID', 'geID': 'Genre ID', 'pcst': 'Podcast',
        'purl': 'Podcast URL', 'egid': 'Episode Global ID',
        'cmID': 'Camera ID', 'sfID': 'Apple Store Country',
        'desc': 'Description', 'ldes': 'Long Description'}
    genre_ids = json.load(open('apple_genres.json'))
```

接下来，我们遍历 MP4 文件的嵌入式元数据键值对。对于每个键，我们使用`qt_tag`字典查找键的人类可读版本。如果值是一个列表，我们将其所有元素连接成一个以分号分隔的字符串。或者，如果值是`"geID"`，我们使用`genre_ids`字典查找整数，并为用户打印映射的类型。

```py
    print("{:22} | {}".format('Name', 'Value'))
    print("-" * 40)
    for name, value in mp4_file.tags.items():
        tag_name = qt_tag.get(name, name)
        if isinstance(value, list):
            value = "; ".join([str(x) for x in value])
        if name == 'geID':
            value = "{}: {}".format(
                value, genre_ids[str(value)].replace("|", " - "))
        print("{:22} | {}".format(tag_name, value))
```

使用 MP3 播客作为示例，脚本显示了其他不可用的详细信息。现在我们知道了发布日期，似乎是使用的软件，以及一些标识符，我们可以用作关键字来尝试在其他地方识别文件。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00031.jpeg)

让我们再看一个播客，但这次是一个 MP4 文件。运行脚本后，我们将得到关于 MP4 文件来源和内容类型的大量信息。同样，由于这个练习，我们可以获得一些有趣的标识符、来源 URL 和其他归因细节。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00032.jpeg)

# 还有更多...

这个脚本可以进一步改进。这里有一个建议：

+   使用`mutagen`库为其他多媒体格式添加额外支持。

# 大局观

食谱难度：简单

Python 版本：2.7 或 3.5

操作系统：任意

图像可以包含许多元数据属性，取决于文件格式和用于拍摄图像的设备。幸运的是，大多数设备会在它们拍摄的照片中嵌入 GPS 信息。使用第三方库，我们将提取 GPS 坐标并在 Google Earth 中绘制它们。这个脚本专注于这个任务，但是这个食谱可以很容易地调整，以提取所有嵌入的**可交换图像文件格式**（**EXIF**）元数据在 JPEG 和 TIFF 图像中。

# 入门

这个食谱需要安装两个第三方库：`pillow`和`simplekml`。此脚本中使用的所有其他库都包含在 Python 的标准库中。`pillow`库提供了一个清晰的接口，用于从图像中提取嵌入的元数据：

```py
pip install pillow==4.2.1
```

要了解更多关于`pillow`库的信息，请访问[`pillow.readthedocs.io/en/4.2.x/`](https://pillow.readthedocs.io/en/4.2.x/)。

为了给这个食谱增添一些额外的风采，我们将把 GPS 详细信息写入一个 KML 文件，以便在类似 Google Earth 的程序中使用。为了处理这个问题，我们将使用`simplekml`库，可以通过执行以下命令进行安装：

```py
pip install simplekml==1.3.0
```

要了解更多关于`simplekml`库的信息，请访问[`www.simplekml.com/en/latest/`](http://www.simplekml.com/en/latest/)。

# 操作步骤如下...

我们按以下步骤从图像文件中提取元数据：

1.  用`PIL`打开输入照片。

1.  使用`PIL`提取所有`EXIF`标签。

1.  如果找到 GPS 坐标，创建一个 Google Earth KML 文件。

1.  打印 Google Maps URL 以在浏览器中查看 GPS 数据。

# 工作原理...

我们首先导入`argparse`以及新安装的`simplekml`和`PIL`库。在本例中，我们只需要从`PIL`中的`Image`和**`ExifTags.Tags`**类。

```py
from __future__ import print_function
import argparse
from PIL import Image
from PIL.ExifTags import TAGS
import simplekml
import sys
```

这个配方的命令行处理程序接受一个位置参数`PICTURE_FILE`，它代表要处理的照片的文件路径。

```py
parser = argparse.ArgumentParser(
    description=__description__,
    epilog="Developed by {} on {}".format(", ".join(__authors__), __date__)
)
parser.add_argument('PICTURE_FILE', help="Path to picture")
args = parser.parse_args()
```

配置这些参数后，我们指定两个 URL，`gmaps`和`open_maps`，我们将用坐标信息填充它们。由于`PIL`库以**度分秒**（**DMS**）格式的元组元组提供坐标，我们需要一个函数将它们转换为另一种常用的坐标表示格式——十进制。提供的元组中的三个元素分别代表坐标的不同组成部分。此外，在每个元组中，有两个元素：第一个元素代表值，第二个元素是必须用来将值转换为整数的比例。

对于坐标的每个组成部分，我们需要将嵌套元组中的第一个值除以第二个值。这种结构用于描述 DMS 坐标的第二个和第三个元组，此外，我们需要确保通过将每个值除以当前迭代计数的`60`的乘积来正确地将分钟和秒相加（这将是`1`和`2`）。虽然这不会改变第一个值（因为枚举从零开始），但它将确保第二和第三个值被正确表示。

以下代码块突出了`PIL`库提供的坐标格式的示例。请注意，度、分和秒值被分组到它们自己的元组中。第一个元素代表坐标的值，第二个代表比例。例如，对于秒元素（第三个元组），我们需要在执行其他操作之前将整数除以`1000`，以确保值被正确表示。

+   **纬度**：`((41 , 1), (53 , 1), (23487 , 1000))`

+   **经度**：`((12 , 1), (29 , 1), (10362 , 1000))`

+   **GPS 坐标**：`41.8898575 , 12.486211666666666`

```py
gmaps = "https://www.google.com/maps?q={},{}"
open_maps = "http://www.openstreetmap.org/?mlat={}&mlon={}"

def process_coords(coord):
    coord_deg = 0
    for count, values in enumerate(coord):
        coord_deg += (float(values[0]) / values[1]) / 60**count
    return coord_deg
```

配置了 DMS 到十进制坐标转换过程后，我们使用`Image.open()`方法打开图像，以将文件路径作为`PIL`对象打开。然后，我们使用`_getexif()`方法提取包含 EXIF 数据的字典。如果`PIL`无法从照片中提取元数据，这个变量将是`None`。

使用`EXIF`字典，我们遍历键和值，将数值转换为可读的名称。这使用了`PIL`中的`TAGS`字典，它将数值映射到表示标签的`string`。`TAGS`对象的作用方式类似于先前配方中手动指定的映射。

```py
img_file = Image.open(args.PICTURE_FILE)
exif_data = img_file._getexif()

if exif_data is None:
    print("No EXIF data found")
    sys.exit()

for name, value in exif_data.items():
    gps_tag = TAGS.get(name, name)
    if gps_tag is not 'GPSInfo':
        continue
```

一旦找到`GPSInfo`标签，我们提取字典键`1`到`4`中的四个感兴趣的值。成对地，我们存储 GPS 参考并使用先前描述的`process_coords()`方法处理坐标。通过将参考存储为布尔值，我们可以轻松地使用`if`语句来确定 GPS 十进制坐标是正数还是负数。

```py
    lat_ref = value[1] == u'N'
    lat = process_coords(value[2])
    if not lat_ref:
        lat = lat * -1

    lon_ref = value[3] == u'E'
    lon = process_coords(value[4])
    if not lon_ref:
        lon = lon * -1
```

为了添加我们的 KML 支持，我们从`simplekml`库初始化一个`kml`对象。从那里，我们添加一个新的点，带有一个名称和坐标。对于名称，我们简单地使用文件的名称。坐标被提供为一个元组，其中第一个元素是经度，第二个元素是纬度。我们也可以在这个元组中提供第三个元素来指定缩放级别，尽管在这种情况下我们省略了它。为了生成我们的`KML`文件，我们调用`save()`方法并将其写入一个与输入文件同名的`.kml`文件。

```py
    kml = simplekml.Kml()
    kml.newpoint(name=args.PICTURE_FILE, coords=[(lon, lat)])
    kml.save(args.PICTURE_FILE + ".kml")
```

有了处理过的 GPS 信息，我们可以在控制台上打印坐标、KML 文件和 URL。注意我们如何嵌套格式字符串，允许我们打印基本消息以及 URL。

```py
    print("GPS Coordinates: {}, {}".format(lat, lon))
    print("Google Maps URL: {}".format(gmaps.format(lat, lon)))
    print("OpenStreetMap URL: {}".format(open_maps.format(lat, lon)))
    print("KML File {} created".format(args.PICTURE_FILE + ".kml"))
```

当我们在命令行上运行这个脚本时，我们很快就能看到坐标、两个链接以查看地图上的位置，以及 KML 文件的路径。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00033.jpeg)

根据我们生成的两个链接，我们可以在两个地图上看到标记，并在需要时与其他人分享这些链接。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00034.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00035.jpeg)

最后，我们可以使用 KML 文件来存储和引用图像中找到的位置。Google Earth 允许通过 Web 和桌面客户端查看这个文件。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00036.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了一个或多个建议如下：

+   集成文件递归以处理多张照片，创建包含许多 GPS 坐标的更大的 KML 文件。

+   尝试使用`simplekml`库为每个点添加额外的细节，比如描述、时间戳、着色等。

# 挖掘 PDF 元数据

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

虽然 PDF 文档可以表示各种各样的媒体，包括图像、文本和表单，但它们包含结构化的嵌入式元数据，以**可扩展元数据平台**（**XMP**）格式提供了一些额外的信息。通过这个配方，我们使用 Python 访问 PDF 并提取描述文档创建和传承的元数据。

# 入门

这个配方需要安装第三方库`PyPDF2`。这个脚本中使用的所有其他库都包含在 Python 的标准库中。`PyPDF2`模块为我们提供了读写 PDF 文件的绑定。在我们的情况下，我们只会使用这个库来读取以 XMP 格式存储的元数据。要安装这个库，请运行以下命令：

```py
pip install PyPDF2==1.26.0
```

要了解更多关于`PyPDF2`库的信息，请访问[`mstamy2.github.io/PyPDF2/`](http://mstamy2.github.io/PyPDF2/)。

# 如何做...

为了处理这个配方的 PDF，我们按照以下步骤进行：

1.  用`PyPDF2`打开 PDF 文件并提取嵌入式元数据。

1.  为不同的 Python 对象类型定义自定义打印函数。

1.  打印各种嵌入式元数据属性。

# 它是如何工作的...

首先，我们导入`argparse`、`datetime`和`sys`库，以及新安装的`PyPDF2`模块。

```py
from __future__ import print_function
from argparse import ArgumentParser, FileType
import datetime
from PyPDF2 import PdfFileReader
import sys
```

这个配方的命令行处理程序接受一个位置参数`PDF_FILE`，表示要处理的 PDF 文件的文件路径。对于这个脚本，我们需要将一个打开的文件对象传递给`PdfFileReader`类，所以我们使用`argparse.FileType`处理程序来为我们打开文件。

```py
parser = ArgumentParser(
    description=__description__,
    epilog="Developed by {} on {}".format(", ".join(__authors__), __date__)
)
parser.add_argument('PDF_FILE', help='Path to PDF file',
                    type=FileType('rb'))
args = parser.parse_args()
```

将打开的文件提供给`PdfFileReader`类后，我们调用`getXmpMetadata()`方法来提供一个包含可用 XMP 元数据的对象。如果这个方法返回`None`，我们会在退出之前向用户打印一个简洁的消息。

```py
pdf_file = PdfFileReader(args.PDF_FILE)

xmpm = pdf_file.getXmpMetadata()
if xmpm is None:
    print("No XMP metadata found in document.")
    sys.exit()
```

有了`xmpm`对象准备就绪，我们开始提取和打印相关值。我们提取了许多不同的值，包括标题、创建者、贡献者、描述、创建和修改日期。这些值的定义来自[`wwwimages.adobe.com/content/dam/Adobe/en/devnet/xmp/pdfs/XMP%20SDK%20Release%20cc-2016-08/XMPSpecificationPart1.pdf`](http://wwwimages.adobe.com/content/dam/Adobe/en/devnet/xmp/pdfs/XMP%20SDK%20Release%20cc-2016-08/XMPSpecificationPart1.pdf)。尽管这些元素中的许多是不同的数据类型，我们以相同的方式将它们传递给`custom_print()`方法。让我们看看这个函数是如何工作的。

```py
custom_print("Title: {}", xmpm.dc_title)
custom_print("Creator(s): {}", xmpm.dc_creator)
custom_print("Contributors: {}", xmpm.dc_contributor)
custom_print("Subject: {}", xmpm.dc_subject)
custom_print("Description: {}", xmpm.dc_description)
custom_print("Created: {}", xmpm.xmp_createDate)
custom_print("Modified: {}", xmpm.xmp_modifyDate)
custom_print("Event Dates: {}", xmpm.dc_date)
```

由于存储的 XMP 值可能因用于生成 PDF 的软件而异，我们使用一个名为`custom_print()`的自定义打印处理函数。这使我们可以处理列表、字典、日期和其他值的转换为可读格式。这个函数是可移植的，可以根据需要引入其他脚本。该函数通过一系列`if-elif-else`语句检查输入的`value`是否是支持的对象类型，使用内置的`isinstance()`方法并适当处理它们。如果输入的`value`是不受支持的类型，则会将其打印到控制台。

```py
def custom_print(fmt_str, value):
    if isinstance(value, list):
        print(fmt_str.format(", ".join(value)))
    elif isinstance(value, dict):
        fmt_value = [":".join((k, v)) for k, v in value.items()]
        print(fmt_str.format(", ".join(value)))
    elif isinstance(value, str) or isinstance(value, bool):
        print(fmt_str.format(value))
    elif isinstance(value, bytes):
        print(fmt_str.format(value.decode()))
    elif isinstance(value, datetime.datetime):
        print(fmt_str.format(value.isoformat()))
    elif value is None:
        print(fmt_str.format("N/A"))
    else:
        print("warn: unhandled type {} found".format(type(value)))
```

我们的下一个元数据集包括有关文档渊源和创建的更多细节。`xmp_creatorTool`属性存储有关用于创建资源的软件的信息。另外，我们还可以根据以下两个 ID 推断出额外的渊源信息：

+   `文档 ID`表示一个标识符，通常存储为 GUID，通常在将资源保存到新文件时分配。例如，如果我们创建`DocA.pdf`，然后将其另存为`DocB.pdf`，我们将有两个不同的`文档 ID`。

+   在`文档 ID`之后是第二个标识符`实例 ID`。`实例 ID`通常在每次保存时生成一次。当我们使用新的段落更新`DocA.pdf`并以相同的文件名保存时，此标识符更新的一个例子。

在编辑相同的 PDF 时，您期望`文档 ID`保持不变，而`实例 ID`可能会更新，尽管这种行为可能会因所使用的软件而异。

```py
custom_print("Created With: {}", xmpm.xmp_creatorTool)
custom_print("Document ID: {}", xmpm.xmpmm_documentId)
custom_print("Instance ID: {}", xmpm.xmpmm_instanceId)
```

随后，我们继续提取其他常见的 XMP 元数据，包括语言、发布者、资源类型和类型。资源类型字段应该表示**多用途互联网邮件扩展**（**MIME**）值，而类型字段应该存储**都柏林核心元数据倡议**（***DCMI**）值。

```py
custom_print("Language: {}", xmpm.dc_language)
custom_print("Publisher: {}", xmpm.dc_publisher)
custom_print("Resource Type: {}", xmpm.dc_format)
custom_print("Type: {}", xmpm.dc_type)
```

最后，我们提取软件保存的任何自定义属性。由于这应该是一个字典，我们可以在不使用我们的`custom_print()`函数的情况下打印它。

```py
if xmpm.custom_properties:
    print("Custom Properties:")
    for k, v in xmpm.custom_properties.items():
        print("\t{}: {}".format(k, v))
```

当我们执行脚本时，我们可以快速看到 PDF 中存储的许多属性。请注意`文档 ID`与`实例 ID`不匹配，这表明该文档可能已经从原始 PDF 进行了修改。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00037.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了以下一个或多个建议：

+   探索和集成其他与 PDF 相关的库，如`slate`和`pyocr`：

+   `slate`模块，[`github.com/timClicks/slate`](https://github.com/timClicks/slate)，可以从 PDF 文件中提取文本。

+   `pyocr`模块，[`github.com/openpaperwork/pyocr`](https://github.com/openpaperwork/pyocr)，可用于对 PDF 进行 OCR 以捕获手写文本。

# 审查可执行元数据

食谱难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

在调查过程中，我们可能会识别出潜在可疑或未经授权的可移植可执行文件。这个可执行文件可能很有趣，因为它在系统上的使用时间，它在系统上的位置，或者调查特定的其他属性。无论我们是将其作为恶意软件还是未经授权的实用程序进行调查，我们都需要有能力了解更多关于它的信息。

通过从 Windows 可执行文件中提取嵌入的元数据，我们可以了解构成文件的组件。在这个示例中，我们将公开编译日期，来自节头的有用的**威胁指标**（**IOC**）数据，以及导入和导出的符号。

# 开始

这个示例需要安装第三方库`pefile`。此脚本中使用的所有其他库都包含在 Python 的标准库中。`pefile`模块使我们无需指定 Windows 可执行文件的所有结构。`pefile`库可以这样安装：

```py
pip install pefile==2017.8.1
```

要了解更多关于`pefile`库的信息，请访问[`github.com/erocarrera/pefile`](https://github.com/erocarrera/pefile)。

# 如何做...

我们通过以下步骤从可执行文件中提取元数据：

1.  打开可执行文件并使用`pefile`转储元数据。

1.  如果存在，动态打印元数据到控制台。

# 它是如何工作的...

我们首先导入处理参数、解析日期和与可执行文件交互的库。请注意，我们专门从`pefile`中导入`PE`类，这样我们可以在示例后面直接调用`PE`类的属性和方法。

```py
from __future__ import print_function
import argparse
from datetime import datetime
from pefile import PE
```

这个示例的命令行处理程序接受一个位置参数`EXE_FILE`，即我们将从中提取元数据的可执行文件的路径。我们还将接受一个可选参数`v`，以允许用户决定他们是否希望获得详细或简化的输出。

```py
parser = argparse.ArgumentParser(
    description=__description__,
    epilog="Developed by {} on {}".format(
        ", ".join(__authors__), __date__)
)
parser.add_argument("EXE_FILE", help="Path to exe file")
parser.add_argument("-v", "--verbose", help="Increase verbosity of output",
                    action='store_true', default=False)
args = parser.parse_args()
```

使用`PE`类，我们通过提供文件路径来简单地加载输入可执行文件。使用`dump_dict()`方法，我们将可执行文件数据转储到字典对象中。这个库允许我们通过这个`ped`字典或作为`pe`对象的属性来探索键值对。我们将演示如何使用这两种技术提取嵌入的元数据。

```py
pe = PE(args.EXE_FILE)
ped = pe.dump_dict()
```

让我们从提取基本文件元数据开始，比如嵌入的作者、版本和编译时间。这些元数据存储在`FileInfo`对象的`StringTable`中。使用`for`循环和`if`语句，我们确保提取正确的值，并将字符串`"Unknown"`赋给值为`None`或长度为零的值，以更好地适应将这些数据打印到控制台。提取并打印所有键值对到控制台后，我们继续处理可执行文件的嵌入编译时间，该时间存储在其他地方。

```py
file_info = {}
for structure in pe.FileInfo:
    if structure.Key == b'StringFileInfo':
        for s_table in structure.StringTable:
            for key, value in s_table.entries.items():
                if value is None or len(value) == 0:
                    value = "Unknown"
                file_info[key] = value
print("File Information: ")
print("==================")
for k, v in file_info.items():
    if isinstance(k, bytes):
        k = k.decode()
    if isinstance(v, bytes):
        v = v.decode()
    print("{}: {}".format(k, v))
```

编译时间戳存储在文件中，显示可执行文件的编译日期。`pefile`库为我们解释原始数据，而`Value`键存储原始十六进制值和方括号内解释的日期。我们可以自己解释十六进制值，或者更简单地将解析后的日期字符串转换为`datetime`对象。

我们使用`split()`和`strip()`方法从方括号中提取解析后的日期字符串。在转换之前，必须将缩写的时区（例如 UTC、EST 或 PST）与解析后的日期字符串分开。一旦日期字符串被隔离，我们使用`datetime.strptime()`方法和`datetime`格式化程序来正确转换和打印可执行文件的嵌入编译日期。

```py
# Compile time 
comp_time = ped['FILE_HEADER']['TimeDateStamp']['Value']
comp_time = comp_time.split("[")[-1].strip("]")
time_stamp, timezone = comp_time.rsplit(" ", 1)
comp_time = datetime.strptime(time_stamp, "%a %b %d %H:%M:%S %Y")
print("Compiled on {} {}".format(comp_time, timezone.strip()))
```

我们提取的下一个元素是关于可执行文件部分的元数据。这一次，我们不是使用`pe`对象及其属性，而是使用我们创建的字典对象`ped`来遍历部分并显示部分名称、地址、大小和其内容的`MD5`哈希。这些数据可以添加到您的 IOC 中，以帮助识别环境中此主机和其他主机上的其他恶意文件。

```py
# Extract IOCs from PE Sections 
print("\nSections: ")
print("==========")
for section in ped['PE Sections']:
    print("Section '{}' at {}: {}/{} {}".format(
        section['Name']['Value'], hex(section['VirtualAddress']['Value']),
        section['Misc_VirtualSize']['Value'],
        section['SizeOfRawData']['Value'], section['MD5'])
    )
```

可执行文件中的另一组元数据是其导入和导出的列表。让我们从导入条目开始。首先，我们确保在尝试访问`pe`变量的这个属性之前，该属性存在。如果存在，我们使用两个`for`循环来遍历导入的 DLL，并且如果用户指定了详细输出，遍历 DLL 中的每个导入。如果用户没有指定详细输出，则跳过最内层循环，只向控制台呈现 DLL 名称。从这些循环中，我们提取 DLL 名称、地址和导入名称。我们可以使用`getattr()`内置函数来确保在属性不存在的情况下不会收到任何错误。

```py
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    print("\nImports: ")
    print("=========")
    for dir_entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = dir_entry.dll
        if not args.verbose:
            print(dll.decode(), end=", ")
            continue

        name_list = []
        for impts in dir_entry.imports:
            if getattr(impts, "name", b"Unknown") is None:
                name = b"Unknown"
            else:
                name = getattr(impts, "name", b"Unknown")
            name_list.append([name.decode(), hex(impts.address)])
        name_fmt = ["{} ({})".format(x[0], x[1]) for x in name_list]
        print('- {}: {}'.format(dll.decode(), ", ".join(name_fmt)))
    if not args.verbose:
        print()
```

最后，让我们回顾与导出元数据相关的代码块。因为一些可执行文件可能没有导出，我们使用`hasattr()`函数来确认`DIRECTORY_ENTRY_EXPORT`属性是否存在。如果存在，我们遍历每个符号，并在控制台中以项目符号列表的形式打印每个符号的名称和地址，以更好地区分它们。

```py
# Display Exports, Names, and Addresses 
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    print("\nExports: ")
    print("=========")
    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print('- {}: {}'.format(sym.name.decode(), hex(sym.address)))
```

以 Firefox 安装程序为例，我们能够从可执行文件中提取大量嵌入的元数据属性。这些信息向我们展示了许多东西，比如编译日期；这似乎是一个打包的可执行文件，可能是用 7-Zip 打包的；以及不同部分的哈希值。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00038.jpeg)

当我们对 DLL 运行相同的脚本时，我们看到与可执行文件运行中的许多相同字段，另外还有导出部分。由于输出的长度，我们省略了以下截图中的一些文本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00039.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了一个或多个建议如下：

+   使用我们在第五章中开发的配方，*网络和威胁指标配方*，查询发现的哈希值与 VirusTotal 等在线资源，并报告其他提交的任何匹配项。

+   集成`pytz`以允许用户在本地或其他指定的时区解释日期

# 读取办公文件元数据

配方难度：中等

Python 版本：2.7 或 3.5

操作系统：任何

从办公文件中读取元数据可以暴露有关这些文件的作者和历史的有趣信息。方便的是，2007 格式的`.docx`、`.xlsx`和`.pptx`文件将元数据存储在 XML 中。XML 标记可以很容易地用 Python 处理。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。我们使用内置的`xml`库和`zipfile`库来允许我们访问 ZIP 容器中的 XML 文档。

要了解有关`xml`库的更多信息，请访问[`docs.python.org/3/library/xml.etree.elementtree.html`](https://docs.python.org/3/library/xml.etree.elementtree.html)。

要了解有关`zipfile`库的更多信息，请访问[`docs.python.org/3/library/zipfile.html`](https://docs.python.org/3/library/zipfile.html)[.](https://docs.python.org/3/library/xml.etree.elementtree.html)

# 如何做...

我们通过执行以下步骤提取嵌入的 Office 元数据：

1.  确认输入文件是有效的 ZIP 文件。

1.  从 Office 文件中提取`core.xml`和`app.xml`文件。

1.  解析 XML 数据并打印嵌入的元数据。

# 它是如何工作的...

首先，我们导入`argparse`和`datetime`库，然后是`xml.etree`和`zipfile`库。`ElementTree`类允许我们将 XML 字符串读入一个对象，我们可以通过它进行迭代和解释。

```py
from __future__ import print_function
from argparse import ArgumentParser
from datetime import datetime as dt
from xml.etree import ElementTree as etree
import zipfile
```

这个配方的命令行处理程序接受一个位置参数`Office_File`，即我们将从中提取元数据的办公文件的路径。

```py
parser = argparse.ArgumentParser(
    description=__description__,
    epilog="Developed by {} on {}".format(", ".join(__authors__), __date__)
)
parser.add_argument("Office_File", help="Path to office file to read")
args = parser.parse_args()
```

在处理参数后，我们检查输入文件是否是一个`zipfile`，如果不是，则引发错误。如果是，我们使用`ZipFile`类打开有效的 ZIP 文件，然后访问包含我们感兴趣的元数据的两个 XML 文档。虽然还有其他包含描述文档数据的 XML 文件，但包含最多元数据的是名为`core.xml`和`app.xml`的两个文件。我们将使用`read()`方法从 ZIP 容器中打开这两个 XML 文件，并将返回的字符串直接发送到`etree.fromstring()` XML 解析方法。

```py
# Check if input file is a zipfile
zipfile.is_zipfile(args.Office_File)

# Open the file (MS Office 2007 or later)
zfile = zipfile.ZipFile(args.Office_File)

# Extract key elements for processing
core_xml = etree.fromstring(zfile.read('docProps/core.xml'))
app_xml = etree.fromstring(zfile.read('docProps/app.xml'))
```

有了准备好的 XML 对象，我们可以开始提取感兴趣的数据。我们设置了一个名为`core_mapping`的字典，用于指定我们想要提取的字段作为键名，以及我们想要将它们显示为的值。这种方法使我们能够轻松地打印出对我们重要的值，如果存在的话，还可以使用友好的标题。这个 XML 文件包含了关于文件作者的重要信息。例如，两个作者字段`creator`和`lastModifiedBy`可以显示一个账户修改了另一个用户账户创建的文档的情况。日期值向我们展示了关于文档的创建和修改的信息。此外，像`revision`这样的元数据字段可以给出有关此文档版本数量的一些指示。

```py
# Core.xml tag mapping 
core_mapping = {
    'title': 'Title',
    'subject': 'Subject',
    'creator': 'Author(s)',
    'keywords': 'Keywords',
    'description': 'Description',
    'lastModifiedBy': 'Last Modified By',
    'modified': 'Modified Date',
    'created': 'Created Date',
    'category': 'Category',
    'contentStatus': 'Status',
    'revision': 'Revision'
}
```

在我们的`for`循环中，我们使用`iterchildren()`方法迭代 XML，以访问`core.xml`文件的 XML 根中的每个标签。使用`core_mapping`字典，我们可以有选择地输出特定字段（如果找到的话）。我们还添加了用`strptime()`方法解释日期值的逻辑。

```py
for element in core_xml.getchildren():
    for key, title in core_mapping.items():
        if key in element.tag:
            if 'date' in title.lower():
                text = dt.strptime(element.text, "%Y-%m-%dT%H:%M:%SZ")
            else:
                text = element.text
            print("{}: {}".format(title, text))
```

接下来的列映射集中在`app.xml`文件上。这个文件包含有关文档内容的统计信息，包括总编辑时间和单词、页数和幻灯片的计数。它还包含有关注册在软件中的公司名称和隐藏元素的信息。为了将这些值打印到控制台上，我们使用了与`core.xml`文件相似的一组`for`循环。

```py
app_mapping = {
    'TotalTime': 'Edit Time (minutes)',
    'Pages': 'Page Count',
    'Words': 'Word Count',
    'Characters': 'Character Count',
    'Lines': 'Line Count',
    'Paragraphs': 'Paragraph Count',
    'Company': 'Company',
    'HyperlinkBase': 'Hyperlink Base',
    'Slides': 'Slide count',
    'Notes': 'Note Count',
    'HiddenSlides': 'Hidden Slide Count',
}
for element in app_xml.getchildren():
    for key, title in app_mapping.items():
        if key in element.tag:
            if 'date' in title.lower():
                text = dt.strptime(element.text, "%Y-%m-%dT%H:%M:%SZ")
            else:
                text = element.text
            print("{}: {}".format(title, text))
```

当我们运行脚本并使用示例 Word 文档时，如下所示，关于文档的许多细节都受到质疑。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00040.jpeg)

另外，我们可以在 PPTX 文档上使用脚本并审查与 PPTX 文件相关的特定格式的元数据：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00041.jpeg)

# 将我们的元数据提取器与 EnCase 集成

配方难度：中等

Python 版本：2.7 或 3.5

操作系统：Windows

我们设计的嵌入式元数据提取配方适用于松散文件，而不适用于取证图像中的文件。令人恼火的是，这在我们的流程中增加了一个额外的步骤，需要我们从图像中导出感兴趣的文件进行此类审查。在这个配方中，我们展示了如何将我们的脚本连接到取证工具 EnCase，并在无需从取证图像中导出文件的情况下执行它们。

# 入门

安装了 EnCase 后，我们需要创建一个案件并添加证据文件，就像对待其他案件一样。这个配方演示了在 EnCase V6 中执行此操作所需的步骤，尽管相同的技术也可以应用于后续版本。

在开始之前，我们还需要确保机器上安装了 Python 2.7 或 3.5、我们希望使用的脚本以及所需的依赖项。

# 操作步骤...

我们通过以下步骤将元数据配方与 EnCase 集成：

1.  打开 EnCase V6 并将证据添加到案件中。

1.  使用“查看文件查看器”菜单配置自定义文件查看器，其中包括`EXIF`元数据提取器。

1.  使用新创建的文件查看器在 EnCase 中提取嵌入的照片 GPS 坐标。

# 它是如何工作的...

打开案例后，我们可以查看感兴趣的照片的十六进制，以确认我们可以在文件中看到`EXIF`头。在这个头部之后是脚本处理的原始值。确定了一个好的候选者后，让我们看看如何配置 EnCase 来运行脚本。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00042.jpeg)

在`查看`菜单下，我们选择`文件查看器`选项。这将打开一个列出可用查看器的选项卡。我们使用的 EnCase 实例没有任何查看器，所以我们必须首先添加任何我们希望使用的查看器。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00043.gif)

在这个选项卡上，右键单击顶层的`文件查看器`元素，然后选择`新建...`来创建我们的自定义查看器。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00044.jpeg)

一个新窗口，如下面的屏幕截图所示，允许我们指定执行脚本的参数。在这个例子中，我们正在实现 GPS 提取脚本，尽管我们可以以同样的方式添加其他脚本。第一行指定了查看器的名称。我们应该给它取一个容易记住的名字，因为在以后选择文件查看器时，这将是我们唯一可用的描述。第二行是可执行文件的路径。在我们的实例中，我们将启动命令提示符，因为我们的 Python 脚本不是一个独立的可执行文件。我们需要为 EnCase 提供`cmd.exe`的完整路径，以便接受这个参数。

最后一行是我们添加脚本的地方。这一行允许我们指定要传递给命令提示符的参数。我们从`/k`开始，以便在脚本完成后保持我们的命令提示符打开。这不是必需的；尽管如果您的代码在控制台上显示信息（就像我们的代码一样），我们应该实现这个功能。否则，命令提示符将在代码完成后立即关闭。在`/k`参数之后，我们提供启动代码的参数。如图所示，这包括 Python 可执行文件和脚本的完整路径。最后一个元素`[file]`是 EnCase 的占位符，在文件查看器执行时被我们要查看的文件替换。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00045.gif)

新的文件查看器条目现在显示在`文件查看器`选项卡中，并显示了我们指定的名称、可执行文件和参数。如果一切看起来正确，我们可以返回到文件条目选项卡中感兴趣的照片。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00046.jpeg)

回到文件条目视图，我们可以右键单击感兴趣的照片，然后从`发送到`子菜单中选择文件查看器。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00047.jpeg)

当我们选择这个选项时，命令窗口会出现，并显示脚本的输出。请注意，KML 文件会自动放置在案例的`Temp`目录中。这是因为我们正在检查的文件在脚本执行期间被缓存在这个目录中。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00048.jpeg)

# 还有更多...

这个过程可以进一步改进。我们提供了一个或多个建议如下：

+   虽然与 Python 无关，但可以考虑 EnScripting 作为自动化和解析多个文件并在 EnCase 控制台选项卡中显示输出的另一个选项。

+   通过类似的方法将本章中涵盖的其他脚本添加到 EnCase 中。由于这些脚本的信息被打印到控制台，我们应该使用`/k`参数，或者重新设计逻辑将输出放在一个目录中。


# 第五章：网络和妥协指标食谱

本章涵盖了以下食谱：

+   用 IEF 快速入门

+   接触 IEF

+   这是一种美丽的汤

+   去寻找病毒

+   情报收集

+   完全被动

# 介绍

技术已经走了很长的路，随之而来的是工具的广泛可用性也发生了变化。事实上，由于互联网上可用的工具数量庞大，知道这些工具的存在已经是一大半的胜利。其中一些工具是公开可用的，并且可以用于取证目的。在本章中，我们将学习如何通过 Python 与网站互动，并识别恶意软件，包括自动审查潜在恶意域、IP 地址或文件。

我们首先看一下如何操纵**Internet Evidence Finder**（**IEF**）的结果，并在应用程序的上下文之外执行额外的处理。我们还探讨了使用 VirusShare、PassiveTotal 和 VirusTotal 等服务来创建已知恶意软件的哈希集，查询可疑域名解析，并分别识别已知的恶意域或文件。在这些脚本之间，您将熟悉使用 Python 与 API 交互。

本章中的脚本专注于解决特定问题，并按复杂性排序：

+   学习从 IEF 结果中提取数据

+   从 Google Chrome 处理缓存的 Yahoo 联系人数据

+   用美丽的汤保存网页

+   从 VirusShare 创建与 X-Ways 兼容的 HashSet

+   使用 PassiveTotal 自动审查可疑域名或 IP 地址

+   使用 VirusTotal 自动识别已知的恶意文件、域名或 IP

访问[www.packtpub.com/books/content/support](http://www.packtpub.com/books/content/support)下载本章的代码包。

# 用 IEF 快速入门

食谱难度：简单

Python 版本：3.5

操作系统：任何

这个食谱将作为一种快速手段，将 IEF 的所有报告转储到 CSV 文件，并介绍与 IEF 结果交互的方法。IEF 将数据存储在 SQLite 数据库中，在第三章中我们对此进行了相当彻底的探讨，*移动取证食谱的深入研究*。由于 IEF 可以配置为扫描特定类别的信息，因此不能简单地为每个 IEF 数据库转储设置表。相反，我们必须动态确定这些信息，然后与相应的表进行交互。这个食谱将动态识别 IEF 数据库中的结果表，并将它们转储到相应的 CSV 文件中。这个过程可以在任何 SQLite 数据库上执行，以快速将其内容转储到 CSV 文件进行审查。

# 入门

本脚本中使用的所有库都包含在 Python 的标准库中。对于此脚本，请确保在执行程序后生成了 IEF 结果数据库。我们使用的是 IEF 版本 6.8.9.5774 来生成本食谱中使用的数据库。例如，当 IEF 完成处理取证图像时，您应该会看到一个名为`IEFv6.db`的文件。这是我们将在本食谱中与之交互的数据库。

# 如何做…

我们将采用以下步骤从 IEF 结果数据库中提取数据：

1.  连接到数据库。

1.  查询数据库以识别所有表。

1.  将结果表写入单独的 CSV 文件。

# 它是如何工作的…

首先，我们导入所需的库来处理参数解析、编写电子表格和与 SQLite 数据库交互。

```py
from __future__ import print_function
import argparse
import csv
import os
import sqlite3
import sys
```

这个食谱的命令行处理程序相对简单。它接受两个位置参数，`IEF_DATABASE`和`OUTPUT_DIR`，分别表示`IEFv6.db`文件的文件路径和期望的输出位置。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("IEF_DATABASE", help="Input IEF database")
    parser.add_argument("OUTPUT_DIR", help="Output DIR")
    args = parser.parse_args()
```

在调用脚本的`main()`函数之前，我们像往常一样执行输入验证步骤。首先，我们检查输出目录，如果不存在则创建它。然后，我们确认 IEF 数据库是否如预期存在。如果一切如预期，我们执行`main()`函数，并向其提供两个用户提供的输入：

```py
    if not os.path.exists(args.OUTPUT_DIR):
        os.makedirs(args.OUTPUT_DIR)

    if os.path.exists(args.IEF_DATABASE) and \
            os.path.isfile(args.IEF_DATABASE):
        main(args.IEF_DATABASE, args.OUTPUT_DIR)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.IEF_DATABASE))
        sys.exit(1)
```

`main()`函数开始得相当简单。我们在控制台打印一个状态消息，并创建`sqlite3`连接到数据库以执行必要的 SQLite 查询：

```py
def main(database, out_directory):
    print("[+] Connecting to SQLite database")
    conn = sqlite3.connect(database)
    c = conn.cursor()
```

接下来，我们需要查询数据库以识别所有存在的表。请注意，我们执行了相当复杂的查询来执行此操作。如果您熟悉 SQLite，您可能会摇摇头，想知道为什么我们没有执行`.table`命令。不幸的是，在 Python 中，这并不那么容易。相反，我们必须执行以下命令才能实现所需的目标。

正如我们之前所见，`Cursor`以元组列表的形式返回结果。我们执行的命令返回数据库中每个表的许多细节。在这种情况下，我们只对提取表的名称感兴趣。我们通过列表推导来实现这一点，首先从游标对象中获取所有结果，然后如果名称符合特定标准，将每个结果的第二个元素附加到表列表中。我们选择忽略以`_`开头或以`_DATA`结尾的表名。经过对这些表的审查，我们发现它们包含实际的缓存文件内容，而不是 IEF 为每个记录呈现的元数据。

```py
    print("[+] Querying IEF database for list of all tables to extract")
    c.execute("select * from sqlite_master where type='table'")
    # Remove tables that start with "_" or end with "_DATA"
    tables = [x[2] for x in c.fetchall() if not x[2].startswith('_') and
              not x[2].endswith('_DATA')]
```

有了手头的表名列表，我们现在可以遍历每个表，并将它们的内容提取到一个变量中。在此之前，我们会在控制台打印一个更新状态消息，通知用户脚本的当前执行状态。为了编写 CSV 文件，我们需要首先确定给定表的列名。这是通过使用`pragma table_info`命令来执行的，正如我们在第三章中看到的那样。通过一些简单的列表推导，我们提取列名，并将它们存储在一个变量中以备后用。

完成这些工作后，我们执行最喜欢和最简单的 SQL 查询，并从每个表中选择所有(`*`)数据。通过在游标对象上使用`fetchall()`方法，我们将包含表数据的元组列表以其完整形式存储在`table_data`变量中：

```py
    print("[+] Dumping {} tables to CSV files in {}".format(
        len(tables), out_directory))
    for table in tables:
        c.execute("pragma table_info('{}')".format(table))
        table_columns = [x[1] for x in c.fetchall()]
        c.execute("select * from '{}'".format(table))
        table_data = c.fetchall()
```

现在我们可以开始将每个表的数据写入其相应的 CSV 文件。为了保持简单，每个 CSV 文件的名称只是表名和附加的`.csv`扩展名。我们使用`os.path.join()`将输出目录与所需的 CSV 名称结合起来。

接下来，我们在控制台打印一个状态更新，并开始编写每个 CSV 文件的过程。首先，我们将表的列名作为电子表格的标题写入，然后是表的内容。我们使用`writerows()`方法将元组列表一次性写入一行，而不是创建一个不必要的循环，并对每个元组执行`writerow()`。

```py
        csv_name = table + '.csv'
        csv_path = os.path.join(out_directory, csv_name)
        print('[+] Writing {} table to {} CSV file'.format(table,
                                                           csv_name))
        with open(csv_path, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(table_columns)
            csv_writer.writerows(table_data)
```

当我们运行这个脚本时，我们可以看到发现的文物，并提取文本信息的 CSV 报告：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00049.jpeg)

完成脚本后，我们可以看到关于文物的信息，如下面报告片段所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00050.jpeg)

# 接触 IEF

食谱难度：中等

Python 版本：3.5

操作系统：任意

我们可以进一步利用 IEF 在 SQLite 数据库中的结果，通过操作和从 IEF 不一定支持的文物中获取更多信息。当发现并不受支持的新文物时，这可能特别重要。由于互联网和许多使用互联网的企业不断变化，软件无法跟上每个新文物。在这种情况下，我们将查看在使用 Yahoo Mail 时存储在本地系统上的缓存的 Yahoo Mail 联系人。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。与前一个配方一样，如果您想跟着做，您将需要一个 IEF 结果数据库。我们使用 IEF 版本 6.8.9.5774 生成了用于开发此配方的数据库。除此之外，您可能需要生成 Yahoo Mail 流量，以创建必要的情况，其中 Yahoo Mail 联系人被缓存。在这个例子中，我们使用 Google Chrome 浏览器使用 Yahoo Mail，因此将查看 Google Chrome 缓存数据。这个配方虽然专门针对 Yahoo，但说明了您可以使用 IEF 结果数据库进一步处理工件并识别其他相关信息。

# 如何做...

该配方遵循以下基本原则：

1.  连接到输入数据库。

1.  查询 Google Chrome 缓存表以获取 Yahoo Mail 联系人记录。

1.  处理联系人缓存 JSON 数据和元数据。

1.  将所有相关数据写入 CSV。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析、编写电子表格、处理 JSON 数据和与 SQLite 数据库交互。

```py
from __future__ import print_function
import argparse
import csv
import json
import os
import sqlite3
import sys
```

这个配方的命令行处理程序与第一个配方没有区别。它接受两个位置参数，`IEF_DATABASE`和`OUTPUT_DIR`，分别表示`IEFv6.db`文件的文件路径和所需的输出位置。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("IEF_DATABASE", help="Input IEF database")
    parser.add_argument("OUTPUT_CSV", help="Output CSV")
    args = parser.parse_args()
```

再次执行与本章第一个配方中执行的相同的数据验证步骤。如果它没有问题，为什么要修复它呢？验证后，执行`main()`函数并向其提供两个经过验证的输入。

```py
    directory = os.path.dirname(args.OUTPUT_CSV)
    if not os.path.exists(directory):
        os.makedirs(directory)

    if os.path.exists(args.IEF_DATABASE) and \
            os.path.isfile(args.IEF_DATABASE):
        main(args.IEF_DATABASE, args.OUTPUT_CSV)
    else:
        print(
            "[-] Supplied input file {} does not exist or is not a "
            "file".format(args.IEF_DATABASE))
        sys.exit(1)
```

`main()`函数再次通过创建与输入 SQLite 数据库的连接开始（我们承诺这个配方与第一个不同：继续阅读）。

```py
def main(database, out_csv):
    print("[+] Connecting to SQLite database")
    conn = sqlite3.connect(database)
    c = conn.cursor()
```

现在我们可以开始搜索数据库，查找所有 Yahoo Mail 联系人缓存记录的实例。请注意，我们要寻找的 URL 片段与我们的目的非常特定。这应该确保我们不会得到任何错误的结果。URL 末尾的百分号（`%`）是 SQLite 通配符的等效字符。我们在`try`和`except`语句中执行查询，以防输入目录没有 Chrome 缓存记录表，损坏或加密。

```py
    print("[+] Querying IEF database for Yahoo Contact Fragments from "
          "the Chrome Cache Records Table")
    try:
        c.execute(
            "select * from 'Chrome Cache Records' where URL like "
            "'https://data.mail.yahoo.com"
            "/classicab/v2/contacts/?format=json%'")
    except sqlite3.OperationalError:
        print("Received an error querying the database -- database may be"
              "corrupt or not have a Chrome Cache Records table")
        sys.exit(2)
```

如果我们能够成功执行查询，我们将返回的元组列表存储到`contact_cache`变量中。这个变量作为`process_contacts()`函数的唯一输入，该函数返回一个方便 CSV 写入器的嵌套列表结构。

```py
    contact_cache = c.fetchall()
    contact_data = process_contacts(contact_cache)
    write_csv(contact_data, out_csv)
```

`process_contacts()`函数首先通过向控制台打印状态消息，设置`results`列表，并迭代每个联系人缓存记录来开始。每个记录都有一些与之相关的元数据元素，除了原始数据之外。这包括 URL、文件系统上缓存的位置以及第一次访问、最后一次访问和最后同步时间的时间戳。

我们使用`json.loads()`方法将从表中提取的 JSON 数据存储到`contact_json`变量中，以便进一步操作。JSON 数据中的`total`和`count`键存储了 Yahoo Mail 联系人的总数以及 JSON 缓存数据中存在的联系人数。

```py
def process_contacts(contact_cache):
    print("[+] Processing {} cache files matching Yahoo contact cache "
          " data".format(len(contact_cache)))
    results = []
    for contact in contact_cache:
        url = contact[0]
        first_visit = contact[1]
        last_visit = contact[2]
        last_sync = contact[3]
        loc = contact[8]
        contact_json = json.loads(contact[7].decode())
        total_contacts = contact_json["total"]
        total_count = contact_json["count"]
```

在从联系人 JSON 中提取联系人数据之前，我们需要确保它首先有联系人。如果没有，我们继续到下一个缓存记录，希望在那里找到联系人。另一方面，如果我们有联系人，我们将一些变量初始化为空字符串。通过将变量批量分配给一组空字符串的元组，在一行中实现了这一点：

```py
        if "contacts" not in contact_json:
            continue

        for c in contact_json["contacts"]:
            name, anni, bday, emails, phones, links = (
                "", "", "", "", "", "")
```

有了这些初始化的变量，我们开始在每个联系人中查找它们。有时特定的缓存记录不会保留完整的联系人详细信息，比如`"anniversary"`键。因此，我们初始化了这些变量，以避免在给定缓存记录中不存在特定键时引用不存在的变量。

对于`name`，`"anniversary"`和`"birthday"`键，我们需要执行一些字符串连接，以便它们以方便的格式。`emails`，`phones`和`links`变量可能有多个结果，因此我们使用列表推导和`join()`方法来创建这些相应元素的逗号分隔列表。这行代码的好处是，如果只有一个电子邮件、电话号码或链接，它不会不必要地在该元素之后放置逗号。

```py
            if "name" in c:
                name = c["name"]["givenName"] + " " + \
                    c["name"]["middleName"] + " " + c["name"]["familyName"]
            if "anniversary" in c:
                anni = c["anniversary"]["month"] + \
                    "/" + c["anniversary"]["day"] + "/" + \
                    c["anniversary"]["year"]
            if "birthday" in c:
                bday = c["birthday"]["month"] + "/" + \
                    c["birthday"]["day"] + "/" + c["birthday"]["year"]
            if "emails" in c:
                emails = ', '.join([x["ep"] for x in c["emails"]])
            if "phones" in c:
                phones = ', '.join([x["ep"] for x in c["phones"]])
            if "links" in c:
                links = ', '.join([x["ep"] for x in c["links"]])
```

我们通过使用`get()`方法来处理`company`，`jobTitle`和`notes`部分。因为这些是简单的键值对，所以我们不需要对它们进行任何额外的字符串处理。相反，使用`get()`方法，我们可以提取键的值，或者如果不存在，则将默认值设置为空字符串。

```py
            company = c.get("company", "")
            title = c.get("jobTitle", "")
            notes = c.get("notes", "")
```

在我们处理完联系数据后，我们将元数据和提取的数据元素的列表附加到`results`列表中。一旦我们处理完每个联系人和每个缓存记录，我们将`results`列表返回到`main()`函数，然后传递给 CSV 写入函数。

```py
            results.append([
                url, first_visit, last_visit, last_sync, loc, name, bday,
                anni, emails, phones, links, company, title, notes,
                total_contacts, total_count])
    return results
```

`write_csv()`方法接受嵌套的`results`列表结构和输出文件路径作为其输入。在我们向控制台打印状态消息后，我们采用通常的策略将结果写入输出文件。换句话说，我们首先写入 CSV 的标题，然后是实际的联系数据。由于嵌套的列表结构，我们可以使用`writerows()`方法将所有结果一次性写入文件。

```py
def write_csv(data, output):
    print("[+] Writing {} contacts to {}".format(len(data), output))
    with open(output, "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow([
            "URL", "First Visit (UTC)", "Last Visit (UTC)",
            "Last Sync (UTC)", "Location", "Contact Name", "Bday",
            "Anniversary", "Emails", "Phones", "Links", "Company", "Title",
            "Notes", "Total Contacts", "Count of Contacts in Cache"])
        csv_writer.writerows(data)
```

此屏幕截图说明了此脚本可以提取的数据类型的示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00051.jpeg)

# 美丽的汤

配方难度：中等

Python 版本：3.5

操作系统：任何

在这个配方中，我们创建一个网站保存工具，利用**Beautiful Soup**库。这是一个用来处理标记语言（如 HTML 或 XML）的库，可以用来轻松处理这些类型的数据结构。我们将使用它来识别和提取网页中的所有链接，只需几行代码。这个脚本旨在展示一个非常简单的网站保存脚本的例子；它绝不打算取代市场上已有的现有软件。

# 入门

此配方需要安装第三方库`bs4`。可以通过以下命令安装此模块。此脚本中使用的所有其他库都包含在 Python 的标准库中。

```py
pip install bs4==0.0.1
```

了解更多关于`bs4`库的信息；访问[`www.crummy.com/software/BeautifulSoup/bs4/doc/`](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)。

# 如何做...

在这个配方中，我们将执行以下步骤：

1.  访问索引网页并识别所有初始链接。

1.  递归遍历所有已知链接以：

1.  查找其他链接并将它们添加到队列中。

1.  生成每个网页的`SHA-256`哈希。

1.  将网页输出写入目标目录，然后验证。

1.  记录相关活动和哈希结果。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析、解析 HTML 数据、解析日期、哈希文件、记录数据和与网页交互。我们还设置一个变量，用于稍后构建配方的日志组件。

```py
from __future__ import print_function
import argparse
from bs4 import BeautifulSoup, SoupStrainer
from datetime import datetime
import hashlib
import logging
import os
import ssl
import sys
from urllib.request import urlopen
import urllib.error

logger = logging.getLogger(__name__)
```

此配方的命令行处理程序接受两个位置输入，`DOMAIN`和`OUTPUT_DIR`，分别表示要保存的网站 URL 和所需的输出目录。可选的`-l`参数可用于指定日志文件路径的位置。

```py
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("DOMAIN", help="Website Domain")
    parser.add_argument("OUTPUT_DIR", help="Preservation Output Directory")
    parser.add_argument("-l", help="Log file path",
                        default=__file__[:-3] + ".log")
    args = parser.parse_args()
```

我们现在将为脚本设置日志记录，使用默认或用户指定的路径。使用*第一章*中的日志格式，我们指定文件和流处理程序，以保持用户在循环中并记录获取过程。

```py
    logger.setLevel(logging.DEBUG)
    msg_fmt = logging.Formatter("%(asctime)-15s %(funcName)-10s"
                                "%(levelname)-8s %(message)s")
    strhndl = logging.StreamHandler(sys.stderr)
    strhndl.setFormatter(fmt=msg_fmt)
    fhndl = logging.FileHandler(args.l, mode='a')
    fhndl.setFormatter(fmt=msg_fmt)

    logger.addHandler(strhndl)
    logger.addHandler(fhndl)
```

设置日志后，我们记录了脚本的执行上下文的一些细节，包括提供的参数和操作系统的详细信息。

```py
    logger.info("Starting BS Preservation")
    logger.debug("Supplied arguments: {}".format(sys.argv[1:]))
    logger.debug("System " + sys.platform)
    logger.debug("Version " + sys.version)
```

我们对所需的输出目录进行了一些额外的输入验证。在这些步骤之后，我们调用`main（）`函数并将网站 URL 和输出目录传递给它。

```py
    if not os.path.exists(args.OUTPUT_DIR):
        os.makedirs(args.OUTPUT_DIR)

    main(args.DOMAIN, args.OUTPUT_DIR)
```

`main（）`函数用于执行一些任务。首先，它通过删除实际名称之前的任何不必要元素来提取网站的基本名称。例如，[`google.com`](https://google.com)变成[google.com](https://google.com)。我们还创建了集合`link_queue`，它将保存在网页上找到的所有唯一链接。

我们对输入 URL 进行了一些额外的验证。在开发过程中，当 URL 没有以`https://`或`http://`开头时，我们遇到了一些错误，因此我们检查这种情况是否存在，并在这种情况下退出脚本并告知用户需求。如果一切正常，我们准备访问基本网页。为此，我们创建未经验证的 SSL 上下文以避免访问网页时出现错误。

```py
def main(website, output_dir):
    base_name = website.replace(
        "https://", "").replace("http://", "").replace("www.", "")
    link_queue = set()
    if "http://" not in website and "https://" not in website:
        logger.error(
            "Exiting preservation - invalid user input: {}".format(
                website))
        sys.exit(1)
    logger.info("Accessing {} webpage".format(website))
    context = ssl._create_unverified_context()
```

接下来，在一个`try-except`块中，我们使用`urlopen（）`方法打开一个到网站的连接，并使用未经验证的 SSL 上下文读取网页数据。如果在尝试访问网页时收到错误，我们会在退出脚本之前打印和记录状态消息。如果成功，我们会记录成功消息并继续脚本执行。

```py
    try:
        index = urlopen(website, context=context).read().decode("utf-8")
    except urllib.error.HTTPError as e:
        logger.error(
            "Exiting preservation - unable to access page: {}".format(
                website))
        sys.exit(2)
    logger.debug("Successfully accessed {}".format(website))
```

对于这个第一个网页，我们调用`write_output（）`函数将其写入输出目录，并调用`find_links（）`函数来识别网页上的所有链接。具体来说，此函数尝试识别网站上的所有内部链接。我们将立即探索这两个函数。

在识别第一页上的链接后，我们在控制台上打印两条状态消息，然后调用`recurse_pages（）`方法来迭代并发现发现的网页上的所有链接，并将它们添加到队列集合中。这完成了`main（）`函数；现在让我们来看一下支持函数的配角，从`write_output（）`方法开始。

```py
    write_output(website, index, output_dir)
    link_queue = find_links(base_name, index, link_queue)
    logger.info("Found {} initial links on webpage".format(
        len(link_queue)))
    recurse_pages(website, link_queue, context, output_dir)
    logger.info("Completed preservation of {}".format(website))
```

`write_output（）`方法需要一些参数：网页的 URL，页面数据，输出目录和一个可选的计数器参数。默认情况下，如果在函数调用中未提供此参数，则将其设置为零。计数器参数用于将循环迭代号附加到输出文件，以避免覆盖同名文件。我们首先删除输出文件名中的一些不必要的字符，这可能会导致创建不必要的目录。我们还将输出目录与 URL 目录连接起来，并使用`os.makedirs（）`创建它们。

```py
def write_output(name, data, output_dir, counter=0):
    name = name.replace("http://", "").replace("https://", "").rstrip("//")
    directory = os.path.join(output_dir, os.path.dirname(name))
    if not os.path.exists(directory) and os.path.dirname(name) != "":
        os.makedirs(directory)
```

现在，我们记录一些关于我们正在写的网页的细节。首先，我们记录文件的名称和输出目的地。然后，我们记录从网页中读取的数据的哈希值，使用`hash_data（）`方法。我们为输出文件创建路径变量，并附加计数器字符串以避免覆盖资源。然后，我们打开输出文件并将网页内容写入其中。最后，我们通过调用`hash_file（）`方法记录输出文件的哈希值。

```py
    logger.debug("Writing {} to {}".format(name, output_dir))
    logger.debug("Data Hash: {}".format(hash_data(data)))
    path = os.path.join(output_dir, name)
    path = path + "_" + str(counter)
    with open(path, "w") as outfile:
        outfile.write(data)
    logger.debug("Output File Hash: {}".format(hash_file(path)))
```

`hash_data（）`方法实际上非常简单。我们读取 UTF-8 编码的数据，然后使用与之前的方法相同的方法生成其`SHA-256`哈希。

```py
def hash_data(data):
    sha256 = hashlib.sha256()
    sha256.update(data.encode("utf-8"))
    return sha256.hexdigest()
```

`hash_file（）`方法稍微复杂一些。在我们可以对数据进行哈希之前，我们必须首先打开文件并将其内容读入`SHA-256`算法中。完成后，我们调用`hexdigest（）`方法并返回生成的`SHA-256`哈希。现在让我们转向`find_links（）`方法以及我们如何利用`BeautifulSoup`快速找到所有相关链接。

```py
def hash_file(file):
    sha256 = hashlib.sha256()
    with open(file, "rb") as in_file:
        sha256.update(in_file.read())
    return sha256.hexdigest()
```

`find_links()` 方法在其初始的 `for` 循环中完成了一些事情。首先，我们从网页数据创建了一个 `BeautifulSoup` 对象。其次，在创建该对象时，我们指定只处理文档的一部分，具体来说是 `<a href>` 标签。这有助于限制 CPU 周期和内存使用，并且允许我们只关注相关的内容。`SoupStrainer` 对象是一个过滤器的花哨名称，在这种情况下，它只过滤 `<a href>` 标签。

有了链接列表之后，我们创建一些逻辑来测试它们是否属于该域。在这种情况下，我们通过检查网站的 URL 是否属于该链接来实现这一点。通过这个测试的任何链接都不能以`#`符号开头。在测试过程中，我们发现在其中一个网站上，这会导致内部页面引用或命名锚点被添加为单独的页面，这是不可取的。通过这些测试的链接被添加到集合队列中（除非它已经存在于集合对象中）。处理所有这样的链接后，队列将返回到调用函数。`recurse_pages()` 函数多次调用此函数，以查找我们索引的每个页面中的所有链接。

```py
def find_links(website, page, queue):
    for link in BeautifulSoup(page, "html.parser",
                              parse_only=SoupStrainer("a", href=True)):
        if website in link.get("href"):
            if not os.path.basename(link.get("href")).startswith("#"):
                queue.add(link.get("href"))
    return queue
```

`recurse_pages()` 函数的输入包括网站 URL、当前链接队列、未经验证的 SSL 上下文和输出目录。我们首先创建一个已处理列表，以跟踪我们已经探索过的链接。我们还设置循环计数器，稍后将其传递给 `write_output()` 函数，以唯一命名输出文件。

接下来，我们开始可怕的 `while True` 循环，这种迭代方式总是有些危险，但在这种情况下，它用于继续迭代队列，随着我们发现更多页面，队列会变得越来越大。在这个循环中，我们将计数器增加 `1`，但更重要的是，检查已处理列表的长度是否与所有找到的链接的长度相匹配。如果是这种情况，循环将被中断。但在满足这种情况之前，脚本将继续迭代所有链接，寻找更多内部链接并将它们写入输出目录。

```py
def recurse_pages(website, queue, context, output_dir):
    processed = []
    counter = 0
    while True:
        counter += 1
        if len(processed) == len(queue):
            break
```

我们开始迭代队列的副本，处理每个链接。我们使用 `set` 的 `copy()` 命令，以便我们可以更新队列而不在其迭代循环中生成错误。如果链接已经被处理，我们继续到下一个链接，以避免执行冗余任务。如果这是第一次处理该链接，则不执行 `continue` 命令，而是将此链接附加到已处理列表中，以便将来不会再次处理。

```py
        for link in queue.copy():
            if link in processed:
                continue
            processed.append(link)
```

我们尝试打开并读取每个链接的数据。如果我们无法访问网页，我们会打印并记录下来，然后继续执行脚本。这样，我们可以保留所有我们可以访问并且有详细信息的页面，以及我们无法访问和保留的链接的日志。

```py
            try:
                page = urlopen(link, context=context).read().decode(
                    "utf-8")
            except urllib.error.HTTPError as e:
                msg = "Error accessing webpage: {}".format(link)
                logger.error(msg)
                continue
```

最后，对于我们能够访问的每个链接，我们通过传递链接名称、页面数据、输出目录和计数器来将其输出到文件。我们还将 `queue` 对象设置为新集合，其中包含旧 `queue` 的所有元素以及 `find_links()` 方法的任何额外新链接。最终，根据网站的大小可能需要一些时间，我们将处理链接队列中的所有项目，并在打印控制台上的状态消息后退出脚本。

```py
            write_output(link, page, output_dir, counter)
            queue = find_links(website, page, queue)
    logger.info("Identified {} links throughout website".format(
        len(queue)))
```

当我们执行这个脚本时，我们提供网站的 URL、输出文件夹以及日志文件的路径，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00052.jpeg)

然后我们可以在浏览器中打开输出文件并查看保留的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00053.jpeg)

# 还有更多...

我们可以通过许多方式扩展这个脚本，包括：

+   收集 CSS、图片和其他资源

+   使用 selenium 在浏览器中截取渲染的页面

+   设置用户代理以伪装收集

# 寻找病毒

食谱难度：中等

Python 版本：3.5

操作系统：任何

VirusShare 是最大的私人拥有的恶意软件样本收集，拥有超过 2930 万个样本。VirusShare 的一个巨大好处，除了每个恶意软件研究人员的梦想——大量的恶意软件之外，还有免费提供的恶意软件哈希列表。我们可以使用这些哈希来创建一个非常全面的哈希集，并在案件调查中利用它来识别潜在的恶意文件。

要了解更多关于使用`VirusShare`的信息，请访问网站[`virusshare.com/`](https://virusshare.com/)。

在这个示例中，我们演示了如何自动下载来自 VirusShare 的哈希列表，以创建一个以换行符分隔的哈希列表。这个列表可以被法医工具（如 X-Ways）使用来创建一个 HashSet。其他法医工具，例如 EnCase，也可以使用这个列表，但需要使用 EnScript 来成功导入和创建 HashSet。

# 入门

这个示例使用了`tqdm`第三方库来创建一个信息丰富的进度条。`tqdm`模块可以通过以下命令安装。这个示例中使用的所有其他库都是 Python 本身的。

```py
pip install tqdm==4.11.2
```

了解更多关于`tqdm`库的信息；访问[`github.com/noamraph/tqdm`](https://github.com/noamraph/tqdm)。

# 如何做...

在这个示例中，我们将执行以下步骤：

1.  阅读 VirusShare 哈希页面并动态识别最新的哈希列表。

1.  初始化进度条并在所需范围内下载哈希列表。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析、创建进度条和与网页交互。

```py
from __future__ import print_function
import argparse
import os
import ssl
import sys
import tqdm
from urllib.request import urlopen
import urllib.error
```

这个示例的命令行处理程序接受一个位置参数`OUTPUT_HASH`，即我们将创建的哈希集的所需文件路径。一个可选参数`--start`，作为整数捕获，是哈希列表的可选起始位置。VirusShare 维护一个包含恶意软件哈希链接的页面，每个链接包含`65,536`到`131,072`个`MD5`哈希的列表。用户可以指定所需的起始位置，而不是下载所有哈希列表（这可能需要一些时间）。例如，如果一个人之前从 VirusShare 下载了哈希，现在希望下载最新发布的几个哈希列表，这可能会很方便。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("OUTPUT_HASH", help="Output Hashset")
    parser.add_argument("--start", type=int,
                        help="Optional starting location")
    args = parser.parse_args()
```

我们执行标准的输入验证步骤，以确保提供的输入不会导致任何意外错误。我们使用`os.path.dirname()`方法来从文件路径中分离目录路径并检查其是否存在。如果不存在，我们现在创建目录，而不是在尝试写入不存在的目录时遇到问题。最后，我们使用`if`语句，并将`start`参数作为关键字提供给`main()`函数，如果它被提供的话。

```py
    directory = os.path.dirname(args.OUTPUT_HASH)
    if not os.path.exists(directory):
        os.makedirs(directory)

    if args.start:
        main(args.OUTPUT_HASH, start=args.start)
    else:
        main(args.OUTPUT_HASH)
```

`main()`函数是这个示例中唯一的函数。虽然它很长，但任务相对简单，因此额外的函数并不是必要的。请注意函数定义中的`**kwargs`参数。这创建了一个字典，我们可以引用来支持提供的关键字参数。在访问 VirusShare 网站之前，我们设置了一些变量并首先在控制台打印了一个状态消息。我们使用`ssl._create_unverified_context()`来绕过 Python 3.X 中收到的 SSL 验证错误。

```py
def main(hashset, **kwargs):
    url = "https://virusshare.com/hashes.4n6"
    print("[+] Identifying hash set range from {}".format(url))
    context = ssl._create_unverified_context()
```

我们使用`try`和`except`块来使用`urllib.request.urlopen()`方法打开 VirusShare 哈希页面，并使用未经验证的 SSL 上下文。我们使用`read()`方法来读取页面数据并解码为 UTF-8。如果我们尝试访问这个页面时出现错误，我们会在控制台打印状态消息并相应地退出脚本。

```py
    try:
        index = urlopen(url, context=context).read().decode("utf-8")
    except urllib.error.HTTPError as e:
        print("[-] Error accessing webpage - exiting..")
        sys.exit(1)
```

使用下载的页面数据的第一个任务是识别最新的哈希列表。我们通过查找指向 VirusShare 哈希列表的 HTML `href`标签的最后一个实例来实现这一点。例如，一个示例链接可能看起来像"`hashes/VirusShare_00288.md5`"。我们使用字符串切片和方法来从链接中分离哈希数（在前面的示例中为`288`）。现在，我们检查`kwargs`字典，看看是否提供了`start`参数。如果没有，我们将`start`变量设置为零，以下载第一个哈希列表和所有中间的哈希列表，直到并包括最后一个，以创建哈希集。

```py
    tag = index.rfind(r'<a href="hashes/VirusShare_')
    stop = int(index[tag + 27: tag + 27 + 5].lstrip("0"))

    if "start" not in kwargs:
        start = 0
    else:
        start = kwargs["start"]
```

在开始下载哈希列表之前，我们进行一次健全性检查，并验证`start`变量。具体来说，我们检查它是否小于零或大于最新的哈希列表。我们使用`start`和`stop`变量来初始化`for`循环和进度条，因此必须验证`start`变量以避免意外结果。如果用户提供了错误的`start`参数，我们会在控制台打印状态消息并退出脚本。

在最后的健全性检查之后，我们会在控制台打印状态消息，并将`hashes_downloaded`计数器设置为零。我们将在稍后的状态消息中使用这个计数器来记录下载并写入哈希列表的数量。

```py
    if start < 0 or start > stop:
        print("[-] Supplied start argument must be greater than or equal "
              "to zero but less than the latest hash list, "
              "currently: {}".format(stop))
        sys.exit(2)

    print("[+] Creating a hashset from hash lists {} to {}".format(
        start, stop))
    hashes_downloaded = 0
```

正如在第一章中讨论的，*基本脚本和文件信息食谱*，我们可以使用`tqdm.trange()`方法作为内置`range()`方法的替代品来创建循环和进度条。我们为其提供所需的`start`和`stop`整数，并为进度条设置一个比例和描述。由于`range()`的工作方式，我们必须将`stop`整数加 1，以实际下载最后一个哈希列表。

在`for`循环中，我们创建一个基本的 URL，并插入一个五位数来指定适当的哈希列表。我们通过将整数转换为字符串，并使用`zfill()`来确保数字有五个字符，通过在字符串前面添加零直到它有五位数。接下来，和之前一样，我们使用`try`和`except`来打开、读取和解码哈希列表。我们根据任何新行字符来拆分，快速创建一个哈希列表。如果我们遇到访问网页时出现错误，我们会在控制台打印状态消息，并继续执行而不是退出脚本。

```py
    for x in tqdm.trange(start, stop + 1, unit_scale=True,
                         desc="Progress"):
        url_hash = "https://virusshare.com/hashes/VirusShare_"\
                   "{}.md5".format(str(x).zfill(5))
        try:
            hashes = urlopen(
                url_hash, context=context).read().decode("utf-8")
            hashes_list = hashes.split("\n")
        except urllib.error.HTTPError as e:
            print("[-] Error accessing webpage for hash list {}"
                  " - continuing..".format(x))
            continue
```

一旦我们有了哈希列表，我们以`a+`模式打开哈希集文本文件，以便在文本文件底部追加并在文件不存在时创建文件。之后，我们只需要遍历下载的哈希列表，并将每个哈希写入文件。请注意，每个哈希列表都以几行注释开头（由`#`符号表示），因此我们实现逻辑来忽略这些行以及空行。在所有哈希都被下载并写入文本文件后，我们会在控制台打印状态消息，并指示下载的哈希数量。

```py

        with open(hashset, "a+") as hashfile:
            for line in hashes_list:
                if not line.startswith("#") and line != "":
                    hashes_downloaded += 1
                    hashfile.write(line + '\n')

    print("[+] Finished downloading {} hashes into {}".format(
        hashes_downloaded, hashset))
```

当我们运行这个脚本时，哈希开始在本地下载，并存储在指定的文件中，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00054.jpeg)

在预览输出文件时，我们可以看到`MD5`哈希值保存为纯文本。如前所述，我们可以将其直接导入到取证工具中，如 X-Ways，或通过脚本导入，如 EnCase（[`www.forensickb.com/2014/02/enscript-to-create-encase-v7-hash-set.html`](http://www.forensickb.com/2014/02/enscript-to-create-encase-v7-hash-set.html)）。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00055.jpeg)

# 收集情报

食谱难度：中等

Python 版本：3.5

操作系统：任意

在这个配方中，我们使用**VirusTotal**，一个免费的在线病毒、恶意软件和 URL 扫描程序，来自动化审查潜在恶意网站或文件。VirusTotal 在其网站上保留了他们 API 的详细文档。我们将演示如何使用他们记录的 API 对其系统执行基本查询，并将返回的结果存储到 CSV 文件中。

# 入门

要遵循这个配方，您需要首先在 VirusTotal 上创建一个帐户，并在免费公共 API 和私人 API 之间做出选择。公共 API 有请求限制，而私人 API 没有。例如，使用公共 API，我们每分钟限制为 4 次请求，每月限制为 178,560 次请求。有关不同 API 类型的更多详细信息可以在 VirusTotal 的网站上找到。我们将使用`requests`库进行这些 API 调用。可以使用以下命令安装此库：

```py
pip install requests==2.18.4
```

要了解更多关于并使用`VirusTotal`，请访问网站[`www.virustotal.com/`](https://www.virustotal.com/)。了解更多关于`VirusTotal`公共 API 的信息，请访问[`www.virustotal.com/en/documentation/public-api/`](https://www.virustotal.com/en/documentation/public-api/)。了解更多关于`VirusTotal`私人 API 的信息，请访问[`www.virustotal.com/en/documentation/private-api/`](https://www.virustotal.com/en/documentation/private-api/)。

查看您的 API 密钥，您将需要用于脚本的，点击右上角的帐户名称，然后导航到我的 API 密钥。在这里，您可以查看 API 密钥的详细信息并请求私钥。查看以下屏幕截图以获取更多详细信息。此脚本中使用的所有库都包含在 Python 的标准库中。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00056.jpeg)

# 如何操作...

我们使用以下方法来实现我们的目标：

1.  将签名列表读入，作为域和 IP 或文件路径和哈希进行研究。

1.  使用 API 查询 VirusTotal 以获取域和 IP 或文件。

1.  将结果展平成方便的格式。

1.  将结果写入 CSV 文件。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析、创建电子表格、对文件进行哈希处理、解析 JSON 数据以及与网页交互。

```py
from __future__ import print_function
import argparse
import csv
import hashlib
import json
import os
import requests
import sys
import time
```

这个配方的命令行处理程序比正常情况下要复杂一些。它需要三个位置参数，`INPUT_FILE`，`OUTPUT_CSV`和`API_KEY`，分别代表域和 IP 或文件路径的输入文本文件，所需的输出 CSV 位置以及包含要使用的 API 密钥的文本文件。除此之外，还有一些可选参数，`-t`（或`--type`）和`--limit`，用于指定输入文件和文件路径或域的数据类型，并限制请求以符合公共 API 的限制。默认情况下，`type`参数配置为域值。如果添加了`limit`开关，它将具有`True`的布尔值；否则，它将是`False`。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("INPUT_FILE",
                        help="Text File containing list of file paths/"
                             "hashes or domains/IPs")
    parser.add_argument("OUTPUT_CSV",
                        help="Output CSV with lookup results")
    parser.add_argument("API_KEY", help="Text File containing API key")
    parser.add_argument("-t", "--type",
                        help="Type of data: file or domain",
                        choices=("file", "domain"), default="domain")
    parser.add_argument(
        "--limit", action="store_true",
        help="Limit requests to comply with public API key restrictions")
    args = parser.parse_args()
```

接下来，我们对输入文件和输出 CSV 执行标准数据验证过程。如果输入通过了数据验证步骤，我们将所有参数传递给`main()`函数，否则退出脚本。

```py

    directory = os.path.dirname(args.OUTPUT_CSV)
    if not os.path.exists(directory):
        os.makedirs(directory)

    if os.path.exists(args.INPUT_FILE) and os.path.isfile(args.INPUT_FILE):
        main(args.INPUT_FILE, args.OUTPUT_CSV,
             args.API_KEY, args.limit, args.type)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.INPUT_FILE))
        sys.exit(1)

```

`main()`函数首先通过将输入文件读入名为`objects`的集合来开始。在这里使用了一个集合，以减少重复的行和对 API 的重复调用。通过这种方式，我们可以尽量延长不必要地达到公共 API 的限制。

```py
def main(input_file, output, api, limit, type):
    objects = set()
    with open(input_file) as infile:
        for line in infile:
            if line.strip() != "":
                objects.add(line.strip())
```

在读取数据后，我们检查我们读入的数据类型是否属于域和 IP 类别或文件路径。根据类型，我们将数据集发送到适当的函数，该函数将返回 VirusTotal 查询结果给`main()`函数。然后我们将这些结果发送到`write_csv()`方法以写入输出。让我们首先看一下`query_domain()`函数。

```py
    if type == "domain":
        data = query_domain(objects, api, limit)
    else:
        data = query_file(objects, api, limit)
    write_csv(data, output)
```

这个函数首先对 API 密钥文件进行额外的输入验证，以确保在尝试使用该密钥进行调用之前文件存在。如果文件存在，我们将其读入`api`变量中。`json_data`列表将存储从 VirusTotal API 调用返回的 JSON 数据。

```py
def query_domain(domains, api, limit):
    if not os.path.exists(api) and os.path.isfile(api):
        print("[-] API key file {} does not exist or is not a file".format(
            api))
        sys.exit(2)

    with open(api) as infile:
        api = infile.read().strip()
    json_data = []
```

在向控制台打印状态消息后，我们开始循环遍历集合中的每个域名或 IP 地址。对于每个项目，我们将`count`递增一次以跟踪我们已经进行了多少 API 调用。我们创建一个参数字典，并存储要搜索的域名或 IP 和 API 密钥，并将`scan`设置为`1`。通过将`scan`设置为`1`，如果域名或 IP 尚未在 VirusTotal 数据库中，我们将自动提交域名或 IP 进行审查。

我们使用`requests.post()`方法进行 API 调用，查询适当的 URL 并使用参数字典来获取结果。我们使用返回的请求对象上的`json()`方法将其转换为易于操作的 JSON 数据。

```py
    print("[+] Querying {} Domains / IPs using VirusTotal API".format(
        len(domains)))
    count = 0
    for domain in domains:
        count += 1
        params = {"resource": domain, "apikey": api, "scan": 1}
        response = requests.post(
            'https://www.virustotal.com/vtapi/v2/url/report',
            params=params)
        json_response = response.json()
```

如果 API 调用成功并且在 VirusTotal 数据库中找到了数据，我们将 JSON 数据附加到列表中。如果在 VirusTotal 数据库中没有找到数据，我们可以使用 API 在生成报告后检索报告。在这里，为简单起见，我们假设数据已经存在于他们的数据库中，只有在找到结果时才添加结果，而不是等待报告生成（如果项目不存在）。

```py
        if "Scan finished" in json_response["verbose_msg"]:
            json_data.append(json_response)
```

接下来，我们检查`limit`是否为`True`，并且`count`变量是否等于 3。如果是，我们需要等待一分钟，然后才能继续查询以遵守公共 API 的限制。我们向控制台打印状态消息，以便用户了解脚本正在做什么，并使用`time.sleep()`方法暂停脚本执行一分钟。等待了一分钟后，我们将计数重置为零，并开始查询列表中剩余的域名或 IP。完成这个过程后，我们将 JSON 结果列表返回给`main()`函数。

```py
        if limit and count == 3:
            print("[+] Halting execution for a minute to comply with "
                  "public API key restrictions")
            time.sleep(60)
            print("[+] Continuing execution of remaining Domains / IPs")
            count = 0

    return json_data
```

`query_file()`方法类似于我们刚刚探讨的`query_domain()`方法。首先，我们验证 API 密钥文件是否存在，否则退出脚本。验证通过后，我们读取 API 密钥并将其存储在`api`变量中，并实例化`json_data`列表以存储 API JSON 数据。

```py
def query_file(files, api, limit):
    if not os.path.exists(api) and os.path.isfile(api):
        print("[-] API key file {} does not exist or is not a file".format(
            api))
        sys.exit(3)

    with open(api) as infile:
        api = infile.read().strip()
    json_data = []
```

与我们刚刚探讨的`query_domain()`函数不同，我们需要对每个文件路径进行一些额外的验证和处理才能使用它。换句话说，我们需要验证每个文件路径是否有效，然后我们必须对每个文件进行哈希，或者使用签名文件中提供的哈希。我们对这些文件进行哈希处理，因为这是我们在 VirusTotal 数据库中查找它们的方式。请记住，我们假设文件已经存在于数据库中。我们可以使用 API 提交样本并在文件扫描后检索报告。

```py
    print("[+] Hashing and Querying {} Files using VirusTotal API".format(
        len(files)))
    count = 0
    for file_entry in files:
        if os.path.exists(file_entry):
            file_hash = hash_file(file_entry)
        elif len(file_entry) == 32:
            file_hash = file_entry
        else:
            continue
        count += 1
```

让我们快速看一下`file_hash`函数。`hash_file()`方法相对简单。这个函数以文件路径作为唯一输入，并返回该文件的`SHA-256`哈希。我们通过创建一个`hashlib`算法对象，类似于我们在第一章中所做的方式，读取文件数据，每次读取`1,024`字节，然后调用`hexdigest()`方法返回计算出的哈希值。有了这个，让我们看一下`query_file()`方法的其余部分。

```py
def hash_file(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as open_file:
        buff_size = 1024
        buff = open_file.read(buff_size)

        while buff:
            sha256.update(buff)
            buff = open_file.read(buff_size)
    return sha256.hexdigest()
```

`query_file()`方法继续通过创建一个带有 API 密钥和文件哈希的参数字典来查找。同样，我们使用`requests.post()`和`json()`方法进行 API 调用，并将其转换为 JSON 数据。

```py
        params = {"resource": file_hash, "apikey": api}
        response = requests.post(
            'https://www.virustotal.com/vtapi/v2/file/report',
            params=params)
        json_response = response.json()
```

如果 API 调用成功并且文件已经存在于 VirusTotal 数据库中，我们将 JSON 数据附加到列表中。再次，我们对计数和限制进行检查，以确保遵守公共 API 限制。完成所有 API 调用后，我们将 JSON 数据列表返回给`main()`函数进行输出。

```py
        if "Scan finished" in json_response["verbose_msg"]:
            json_data.append(json_response)

        if limit and count == 3:
            print("[+] Halting execution for a minute to comply with "
                  "public API key restrictions")
            time.sleep(60)
            print("[+] Continuing execution of remaining files")
            count = 0

    return json_data
```

`write_csv()`方法首先检查输出数据是否实际包含 API 结果。如果没有，脚本将退出而不是写入空的 CSV 文件。

```py
def write_csv(data, output):
    if data == []:
        print("[-] No output results to write")
        sys.exit(4)
```

如果我们有结果，我们会在控制台上打印状态消息，并开始将 JSON 数据展平为方便的输出格式。我们创建一个`flatten_data`列表，它将存储每个展平的 JSON 字典。字段列表维护了展平的 JSON 字典中键的列表和所需的列标题。

我们使用几个`for`循环来获取 JSON 数据，并将带有这些数据的字典附加到列表中。完成此过程后，我们将拥有一个非常简单的字典结构列表可供使用。我们可以像以前一样使用`csv.DictWriter`类轻松处理这种数据结构。

```py
    print("[+] Writing output for {} domains with results to {}".format(
        len(data), output))
    flatten_data = []
    field_list = ["URL", "Scan Date", "Service",
                  "Detected", "Result", "VirusTotal Link"]
    for result in data:
        for service in result["scans"]:
            flatten_data.append(
                {"URL": result.get("url", ""),
                 "Scan Date": result.get("scan_date", ""),
                 "VirusTotal Link": result.get("permalink", ""),
                 "Service": service,
                 "Detected": result["scans"][service]["detected"],
                 "Result": result["scans"][service]["result"]})
```

准备好输出的数据集后，我们打开 CSV 文件并创建`DictWriter`类实例。我们向它提供文件对象和字典中标题的列表。我们在将每个字典写入行之前将标题写入电子表格。

```py
    with open(output, "w", newline="") as csvfile:
        csv_writer = csv.DictWriter(csvfile, fieldnames=field_list)
        csv_writer.writeheader()
        for result in flatten_data:
            csv_writer.writerow(result)
```

以下截图反映了当我们针对文件和哈希运行脚本时的情况，以及针对域名和 IP 运行脚本时的情况：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00057.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00058.jpeg)

通过查看输出，我们可以了解文件和哈希的恶意软件分类，以及域名或 IP 在 CSV 格式中的排名：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00059.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00060.jpeg)

# 完全被动

教程难度：中等

Python 版本：3.5

操作系统：任何

这个教程探讨了 PassiveTotal API 以及如何使用它来自动审查域名和 IP 地址。这项服务在查看给定域的历史解析详情方面特别有用。例如，您可能有一个被怀疑的钓鱼网站，并且根据历史解析模式，可以确定它已经活跃了多长时间，以及以前有哪些其他域名共享了该 IP。然后，这给您提供了额外的域名来审查和搜索，以便在确定攻击者在整个环境中如何维持持久性的不同手段和方法时，您可以找到证据。

# 入门

要使用 PassiveTotal API，您需要首先在他们的网站上创建一个免费帐户。登录后，您可以通过导航到帐户设置并在 API ACCESS 部分的用户显示按钮下点击查看 API 密钥。请参考以下截图以直观地了解此页面。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00061.jpeg)

此脚本中使用的所有库都包含在 Python 的标准库中。但是，我们确实安装了 PassiveTotal Python API 客户端，并按照 README 中的安装和设置说明在[`github.com/passivetotal/python_api`](https://github.com/passivetotal/python_api)或使用`pip install passivetotal==1.0.30`进行安装。我们这样做是为了使用 PassiveTotal 命令行`pt-client`应用程序。在此脚本中，我们通过此客户端进行 API 调用，而不是像在上一个教程中那样以更手动的方式执行。如果您对 PassiveTotal API 有更多兴趣，尤其是如果您有兴趣开发更高级的东西，可以在他们的网站上找到更多详细信息。

要了解更多关于并使用`PassiveTotal`，请访问网站[`www.passivetotal.org`](https://www.passivetotal.org)。[](https://www.passivetotal.org) 了解更多关于`PassiveTotal` API，请访问[`api.passivetotal.org/api/docs`](https://api.passivetotal.org/api/docs)。[](https://api.passivetotal.org/api/docs) 了解更多关于`PassiveTotal` Python API，请访问[`github.com/passivetotal/python_api`](https://github.com/passivetotal/python_api)。

# 如何做...

我们使用以下方法来实现我们的目标：

1.  读取要审查的域名列表。

1.  使用`subprocess`调用命令行`pt-client`，并为每个域名将结果返回到我们的脚本。

1.  将结果写入 CSV 文件。

# 它是如何工作的...

首先，我们导入所需的库来处理参数解析、创建电子表格、解析 JSON 数据和生成子进程。

```py
from __future__ import print_function
import argparse
import csv
import json
import os
import subprocess
import sys
```

这个配方的命令行处理程序接受两个位置参数，`INPUT_DOMAINS`和`OUTPUT_CSV`，分别用于包含域名和/或 IP 的输入文本文件以及所需的输出 CSV。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("INPUT_DOMAINS",
                        help="Text File containing Domains and/or IPs")
    parser.add_argument("OUTPUT_CSV",
                        help="Output CSV with lookup results")
    args = parser.parse_args()
```

我们对每个输入执行标准的输入验证步骤，以避免脚本中出现意外错误。验证输入后，我们调用`main()`函数并传递这两个输入。

```py
    directory = os.path.dirname(args.OUTPUT_CSV)
    if not os.path.exists(directory):
        os.makedirs(directory)

    if os.path.exists(args.INPUT_DOMAINS) and \
            os.path.isfile(args.INPUT_DOMAINS):
        main(args.INPUT_DOMAINS, args.OUTPUT_CSV)
    else:
        print(
            "[-] Supplied input file {} does not exist or is not a "
            "file".format(args.INPUT_DOMAINS))
        sys.exit(1)
```

`main()` 函数非常简单，与之前的配方类似。我们再次使用集合来读取输入文件中的对象。这是为了避免对 PassiveTotal API 进行冗余的 API 调用，因为免费 API 有每日限制。在读取这些对象之后，我们调用`query_domains()`函数，该函数使用`pt-client`应用程序进行 API 调用。一旦我们从 API 调用中获得了所有返回的 JSON 数据，我们调用`write_csv()`方法将数据写入 CSV 文件。

```py
def main(domain_file, output):
    domains = set()
    with open(domain_file) as infile:
        for line in infile:
            domains.add(line.strip())
    json_data = query_domains(domains)
    write_csv(json_data, output)
```

`query_domains()` 函数首先创建一个`json_data`列表来存储返回的 JSON 数据，并在控制台打印状态消息。然后，我们开始遍历输入文件中的每个对象，并删除任何"`https://`"或"`http://`"子字符串。在测试`pt-client`时，观察到如果存在该子字符串，它会生成内部服务器错误。例如，查询应该是[www.google.com](https://www.google.com)而不是[`www.google.com`](https://www.google.com)。

```py
def query_domains(domains):
    json_data = []
    print("[+] Querying {} domains/IPs using PassiveTotal API".format(
        len(domains)))
    for domain in domains:
        if "https://" in domain:
            domain = domain.replace("https://", "")
        elif "http://" in domain:
            domain = domain.replace("http://", "")
```

准备好查询的域名或 IP 地址后，我们使用`subprocess.Popen()`方法打开一个新进程并执行`pt-client`应用程序。要在此进程中执行的参数在列表中。如果域名是[www.google.com](https://www.google.com)，那么将要执行的命令看起来像`pt-client pdns -q www.gooogle.com`。通过将`stdout`关键字参数设置为`subprocess.PIPE`，我们为进程创建了一个新的管道，以便我们可以从查询中检索结果。我们通过调用`communicate()`方法并将返回的数据转换为 JSON 结构来做到这一点，然后将其存储。

```py
        proc = subprocess.Popen(
            ["pt-client", "pdns", "-q", domain], stdout=subprocess.PIPE)
        results, err = proc.communicate()
        result_json = json.loads(results.decode())
```

如果 JSON 结果中包含`quota_exceeded`消息，则表示我们已超过了每日 API 限制，并将其打印到控制台并继续执行。我们继续执行而不是退出，以便在超过每日 API 配额之前可以写入我们检索到的任何结果。

```py
        if "message" in result_json:
            if "quota_exceeded" in result_json["message"]:
                print("[-] API Search Quota Exceeded")
                continue
```

接下来，我们设置`result_count`并检查它是否等于零。如果查询找到了结果，我们将结果附加到 JSON 列表中。在对输入文件中的所有域名和/或 IP 执行此操作后，我们返回 JSON 列表。

```py
        result_count = result_json["totalRecords"]

        print("[+] {} results for {}".format(result_count, domain))
        if result_count == 0:
            pass
        else:
            json_data.append(result_json["results"])

    return json_data
```

`write_csv()` 方法非常简单。在这里，我们首先检查是否有数据要写入输出文件。然后，我们在控制台打印状态消息，并创建标题列表以及它们应该被写入的顺序。

```py
def write_csv(data, output):
    if data == []:
        print("[-] No output results to write")
        sys.exit(2)

    print("[+] Writing output for {} domains/IPs with "
          "results to {}".format(len(data), output))
    field_list = ["value", "firstSeen", "lastSeen", "collected",
                  "resolve", "resolveType", "source", "recordType",
                  "recordHash"]
```

在创建了标题列表之后，我们使用`csv.DictWriter`类来设置输出 CSV 文件，写入标题行，并遍历 JSON 结果中的每个字典，并将它们写入各自的行。

```py
    with open(output, "w", newline="") as csvfile:
        csv_writer = csv.DictWriter(csvfile, fieldnames=field_list)
        csv_writer.writeheader()
        for result in data:
            for dictionary in result:
                csv_writer.writerow(dictionary)
```

运行脚本可以了解 PassiveTotal 查找中每个项目的响应数量：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00062.jpeg)

CSV 报告显示了收集到的信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00063.jpeg)
