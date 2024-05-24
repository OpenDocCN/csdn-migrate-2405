# Django3 Web 开发秘籍第四版（六）

> 原文：[`zh.annas-archive.org/md5/49CC5D4E5506D0966D8746F9F4B56200`](https://zh.annas-archive.org/md5/49CC5D4E5506D0966D8746F9F4B56200)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：导入和导出数据

在这一章中，我们将涵盖以下主题：

+   从本地 CSV 文件导入数据

+   从本地 Excel 文件导入数据

+   从外部 JSON 文件导入数据

+   从外部 XML 文件导入数据

+   为搜索引擎准备分页站点地图

+   创建可过滤的 RSS 订阅

+   使用 Django REST 框架创建 API

# 介绍

偶尔，您的数据需要从本地格式传输到数据库，从外部资源导入，或者提供给第三方。在这一章中，我们将看一些实际的例子，演示如何编写管理命令和 API 来实现这一点。

# 技术要求

要使用本章的代码，您需要最新稳定版本的 Python、MySQL 或 PostgreSQL 数据库，以及一个带有虚拟环境的 Django 项目。还要确保在虚拟环境中安装 Django、Pillow 和数据库绑定。

您可以在 GitHub 存储库的`ch09`目录中找到本章的所有代码：[`github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition`](https://github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition)。

# 从本地 CSV 文件导入数据

**逗号分隔值**（**CSV**）格式可能是在文本文件中存储表格数据的最简单方式。在这个示例中，我们将创建一个管理命令，将数据从 CSV 文件导入到 Django 数据库中。我们需要一个歌曲的 CSV 列表。您可以使用 Excel、Calc 或其他电子表格应用程序轻松创建这样的文件。

# 准备工作

让我们创建一个`music`应用程序，我们将在本章中使用它：

1.  创建`music`应用程序本身，并将其放在设置中的`INSTALLED_APPS`下：

```py
# myproject/settings/_base.py
INSTALLED_APPS = [
    # …
    "myproject.apps.core",
    "myproject.apps.music",
]
```

1.  `Song`模型应该包含`uuid`、`artist`、`title`、`url`和`image`字段。我们还将扩展`CreationModificationDateBase`以添加创建和修改时间戳，以及`UrlBase`以添加用于处理模型详细 URL 的方法：

```py
# myproject/apps/music/models.py
import os
import uuid
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _
from django.db import models
from django.utils.text import slugify
from myproject.apps.core.models import CreationModificationDateBase, UrlBase

def upload_to(instance, filename):
    filename_base, filename_ext = os.path.splitext(filename)
    artist = slugify(instance.artist)
    title = slugify(instance.title)
    return f"music/{artist}--{title}{filename_ext.lower()}"

class Song(CreationModificationDateBase, UrlBase):
    uuid = models.UUIDField(primary_key=True, default=None, 
     editable=False)
    artist = models.CharField(_("Artist"), max_length=250)
    title = models.CharField(_("Title"), max_length=250)
    url = models.URLField(_("URL"), blank=True)
    image = models.ImageField(_("Image"), upload_to=upload_to, 
     blank=True, null=True)

    class Meta:
        verbose_name = _("Song")
        verbose_name_plural = _("Songs")
        unique_together = ["artist", "title"]

    def __str__(self):
        return f"{self.artist} - {self.title}"

    def get_url_path(self):
        return reverse("music:song_detail", kwargs={"pk": self.pk})

    def save(self, *args, **kwargs):
        if self.pk is None:
            self.pk = uuid.uuid4()
        super().save(*args, **kwargs)
```

1.  使用以下命令创建和运行迁移：

```py
(env)$ python manage.py makemigrations
(env)$ python manage.py migrate
```

1.  然后，让我们为`Song`模型添加一个简单的管理：

```py
# myproject/apps/music/admin.py
from django.contrib import admin
from .models import Song

@admin.register(Song)
class SongAdmin(admin.ModelAdmin):
    list_display = ["title", "artist", "url"]
    list_filter = ["artist"]
    search_fields = ["title", "artist"]
```

1.  此外，我们需要一个用于验证和创建导入脚本中的`Song`模型的表单。它是最简单的模型表单，如下所示：

```py
# myproject/apps/music/forms.py
from django import forms
from django.utils.translation import ugettext_lazy as _
from .models import Song

class SongForm(forms.ModelForm):
    class Meta:
        model = Song
        fields = "__all__" 
```

# 如何做...

按照以下步骤创建和使用一个管理命令，从本地 CSV 文件导入歌曲：

1.  创建一个 CSV 文件，第一行包含列名`artist`、`title`和`url`。在接下来的行中添加一些歌曲数据，与列匹配。例如，可以是一个内容如下的`data/music.csv`文件：

```py
artist,title,url
Capital Cities,Safe And Sound,https://open.spotify.com/track/40Fs0YrUGuwLNQSaHGVfqT?si=2OUawusIT-evyZKonT5GgQ
Milky Chance,Stolen Dance,https://open.spotify.com/track/3miMZ2IlJiaeSWo1DohXlN?si=g-xMM4m9S_yScOm02C2MLQ
Lana Del Rey,Video Games - Remastered,https://open.spotify.com/track/5UOo694cVvjcPFqLFiNWGU?si=maZ7JCJ7Rb6WzESLXg1Gdw
Men I Trust,Tailwhip,https://open.spotify.com/track/2DoO0sn4SbUrz7Uay9ACTM?si=SC_MixNKSnuxNvQMf3yBBg
```

1.  在`music`应用程序中，创建一个`management`目录，然后在新的`management`目录中创建一个`commands`目录。在这两个新目录中都放入空的`__init__.py`文件，使它们成为 Python 包。

1.  在那里添加一个名为`import_music_from_csv.py`的文件，内容如下：

```py
# myproject/apps/music/management/commands/import_music_from_csv.py
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = (
        "Imports music from a local CSV file. "
        "Expects columns: artist, title, url"
    )
    SILENT, NORMAL, VERBOSE, VERY_VERBOSE = 0, 1, 2, 3

    def add_arguments(self, parser):
        # Positional arguments
        parser.add_argument("file_path", nargs=1, type=str)

    def handle(self, *args, **options):
        self.verbosity = options.get("verbosity", self.NORMAL)
        self.file_path = options["file_path"][0]
        self.prepare()
        self.main()
        self.finalize()
```

1.  然后，在`Command`类的同一文件中，创建一个`prepare()`方法：

```py
    def prepare(self):
        self.imported_counter = 0
        self.skipped_counter = 0
```

1.  然后，我们应该创建`main()`方法：

```py
    def main(self):
        import csv
        from ...forms import SongForm

        if self.verbosity >= self.NORMAL:
            self.stdout.write("=== Importing music ===")

        with open(self.file_path, mode="r") as f:
            reader = csv.DictReader(f)
            for index, row_dict in enumerate(reader):
                form = SongForm(data=row_dict)
                if form.is_valid():
                    song = form.save()
                    if self.verbosity >= self.NORMAL:
                        self.stdout.write(f" - {song}\n")
                    self.imported_counter += 1
                else:
                    if self.verbosity >= self.NORMAL:
                        self.stderr.write(
                            f"Errors importing song "
                            f"{row_dict['artist']} - 
                             {row_dict['title']}:\n"
                        )
                        self.stderr.write(f"{form.errors.as_json()}\n")
                    self.skipped_counter += 1
```

1.  我们将使用`finalize()`方法完成这个类：

```py
    def finalize(self)
        if self.verbosity >= self.NORMAL:
            self.stdout.write(f"-------------------------\n")
            self.stdout.write(f"Songs imported:         
             {self.imported_counter}\n")
            self.stdout.write(f"Songs skipped: 
             {self.skipped_counter}\n\n")
```

1.  要运行导入，请在命令行中调用以下命令：

```py
(env)$ python manage.py import_music_from_csv data/music.csv
```

# 它是如何工作的...

Django 管理命令是从`BaseCommand`派生的`Command`类的脚本，并覆盖`add_arguments()`和`handle()`方法。`help`属性定义了管理命令的帮助文本。当您在命令行中输入以下内容时，可以看到它：

```py
(env)$ python manage.py help import_music_from_csv
```

Django 管理命令使用内置的`argparse`模块来解析传递的参数。`add_arguments()`方法定义了应该传递给管理命令的位置或命名参数。在我们的情况下，我们将添加一个 Unicode 类型的位置参数`file_path`。通过将`nargs`变量设置为`1`属性，我们只允许一个值。

要了解您可以定义的其他参数以及如何做到这一点，请参阅官方的`argparse`文档[`docs.python.org/3/library/argparse.html#adding-arguments`](https://docs.python.org/3/library/argparse.html#adding-arguments)。

在`handle()`方法的开始，检查`verbosity`参数。Verbosity 定义了命令应该提供多少终端输出，从 0，不提供任何日志，到 3，提供详尽的日志。您可以将这个命名参数传递给命令，如下所示：

```py
(env)$ python manage.py import_music_from_csv data/music.csv --verbosity=0
```

我们还期望文件名作为第一个位置参数。`options["file_path"]`返回一个值的列表，其长度由`nargs`定义。在我们的情况下，`nargs`等于一；因此，`options["file_path"]`将等于一个元素的列表。

将您的管理命令的逻辑分割成多个较小的方法是一个很好的做法，例如，就像我们在这个脚本中使用的`prepare()`，`main()`和`finalize()`一样：

+   `prepare()`方法将导入计数器设置为零。它也可以用于脚本所需的任何其他设置。

+   在`main()`方法中，我们执行管理命令的主要逻辑。首先，我们打开给定的文件进行读取，并将其指针传递给`csv.DictReader`。文件中的第一行被假定为每列的标题。`DictReader`将它们用作每行的字典的键。当我们遍历行时，我们将字典传递给模型表单，并尝试验证它。如果验证通过，歌曲将被保存，并且`imported_counter`将被递增。如果验证失败，因为值过长，缺少必需值，错误类型或其他验证错误，`skipped_counter`将被递增。如果 verbosity 等于或大于`NORMAL`（即数字 1），每个导入或跳过的歌曲也将与可能的验证错误一起打印出来。

+   `finalize()`方法打印出导入了多少首歌曲，以及因验证错误而被跳过了多少首。

如果您想在开发时调试管理命令的错误，请将`--traceback`参数传递给它。当发生错误时，您将看到问题的完整堆栈跟踪。

假设我们使用`--verbosity=1`或更高的参数两次调用命令，我们可以期望的输出可能如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/669d9ec1-88f7-4d11-922c-f42b822c335f.png)

正如您所看到的，当一首歌被导入第二次时，它不会通过`unique_together`约束，因此会被跳过。

# 另请参阅

+   *从本地 Excel 文件导入数据*食谱

+   *从外部 JSON 文件导入数据*食谱

+   *从外部 XML 文件导入数据*食谱

# 从本地 Excel 文件导入数据

存储表格数据的另一种流行格式是 Excel 电子表格。在这个食谱中，我们将从这种格式的文件中导入歌曲。

# 准备工作

让我们从之前的食谱中创建的`music`应用程序开始。要读取 Excel 文件，您需要安装`openpyxl`包，如下所示：

```py
(env)$ pip install openpyxl==3.0.2

```

# 如何做...

按照以下步骤创建并使用一个管理命令，从本地 XLSX 文件导入歌曲：

1.  创建一个 XLSX 文件，其中包含列名 Artist、Title 和 URL 在第一行。在接下来的行中添加一些与列匹配的歌曲数据。您可以在电子表格应用程序中执行此操作，将前一个食谱中的 CSV 文件保存为 XLSX 文件，`data/music.xlsx`。以下是一个示例：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/593e1328-3062-435a-8fa8-c186382cc759.png)

1.  如果还没有这样做，在`music`应用程序中，创建一个`management`目录，然后在其下创建一个`commands`子目录。在这两个新目录中添加空的`__init__.py`文件，使它们成为 Python 包。

1.  添加一个名为`import_music_from_xlsx.py`的文件，内容如下：

```py
# myproject/apps/music/management/commands
# /import_music_from_xlsx.py
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = (
        "Imports music from a local XLSX file. "
        "Expects columns: Artist, Title, URL"
    )
    SILENT, NORMAL, VERBOSE, VERY_VERBOSE = 0, 1, 2, 3

    def add_arguments(self, parser):
        # Positional arguments
        parser.add_argument("file_path",
                            nargs=1,
                            type=str)

    def handle(self, *args, **options):
        self.verbosity = options.get("verbosity", self.NORMAL)
        self.file_path = options["file_path"][0]
        self.prepare()
        self.main()
        self.finalize()
```

1.  然后，在相同的文件中为`Command`类创建一个`prepare()`方法：

```py
    def prepare(self):
        self.imported_counter = 0
        self.skipped_counter = 0

```

1.  然后，在那里创建`main()`方法：

```py
    def main(self):
        from openpyxl import load_workbook
        from ...forms import SongForm

        wb = load_workbook(filename=self.file_path)
        ws = wb.worksheets[0]

        if self.verbosity >= self.NORMAL:
            self.stdout.write("=== Importing music ===")

        columns = ["artist", "title", "url"]
        rows = ws.iter_rows(min_row=2)  # skip the column captions
        for index, row in enumerate(rows, start=1):
            row_values = [cell.value for cell in row]
            row_dict = dict(zip(columns, row_values))
            form = SongForm(data=row_dict)
            if form.is_valid():
                song = form.save()
                if self.verbosity >= self.NORMAL:
                    self.stdout.write(f" - {song}\n")
                self.imported_counter += 1
            else:
                if self.verbosity >= self.NORMAL:
                    self.stderr.write(
                        f"Errors importing song "
                        f"{row_dict['artist']} - 
                         {row_dict['title']}:\n"
                    )
                    self.stderr.write(f"{form.errors.as_json()}\n")
                self.skipped_counter += 1
```

1.  最后，我们将使用`finalize()`方法完成类：

```py
    def finalize(self):
        if self.verbosity >= self.NORMAL:
            self.stdout.write(f"-------------------------\n")
            self.stdout.write(f"Songs imported: 
             {self.imported_counter}\n")
            self.stdout.write(f"Songs skipped: 
             {self.skipped_counter}\n\n")
```

1.  要运行导入，请在命令行中调用以下命令：

```py
(env)$ python manage.py import_music_from_xlsx data/music.xlsx
```

# 它是如何工作的...

从 XLSX 文件导入的原则与 CSV 相同。我们打开文件，逐行读取，形成数据字典，通过模型表单验证它们，并从提供的数据创建`Song`对象。

同样，我们使用`prepare()`、`main()`和`finalize()`方法将逻辑分割成更多的原子部分。

以下是`main()`方法的详细说明，因为它可能是管理命令的唯一不同部分：

+   Excel 文件是包含不同选项卡的工作簿。

+   我们使用`openpyxl`库打开作为命令的位置参数传递的文件。然后，我们从工作簿中读取第一个工作表。

+   第一行包含列标题。我们跳过它。

+   之后，我们将逐行读取行作为值列表，使用`zip()`函数创建字典，将它们传递给模型表单，验证，并从中创建`Song`对象。

+   如果存在任何验证错误并且 verbosity 大于或等于`NORMAL`，那么我们将输出验证错误。

+   再次，管理命令将把导入的歌曲打印到控制台上，除非您设置`--verbosity=0`。

如果我们使用`--verbosity=1`或更高的参数运行命令两次，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/48543c7a-7dce-4d37-90fd-a1626e570c48.png)

您可以在[`www.python-excel.org/`](http://www.python-excel.org/)了解有关如何处理 Excel 文件的更多信息。

# 另请参阅

+   从本地 CSV 文件导入数据的方法

+   从外部 JSON 文件导入数据的方法

+   从外部 XML 文件导入数据的方法

# 从外部 JSON 文件导入数据

[Last.fm](http://last.fm)音乐网站在[`ws.audioscrobbler.com/`](https://ws.audioscrobbler.com/)域下有一个 API，您可以使用它来读取专辑、艺术家、曲目、事件等等。该 API 允许您使用 JSON 或 XML 格式。在这个方法中，我们将使用 JSON 格式导入标记为`indie`的热门曲目。

# 准备就绪

按照以下步骤从`Last.fm`导入 JSON 格式的数据：

1.  让我们从我们在*从本地 CSV 文件导入数据*方法中创建的`music`应用程序开始。

1.  要使用[Last.fm](http://last.fm)，您需要注册并获取 API 密钥。API 密钥可以是

在[`www.last.fm/api/account/create`](https://www.last.fm/api/account/create)创建。

1.  API 密钥必须在设置中设置为`LAST_FM_API_KEY`。我们建议

从秘密文件提供它或从环境变量中提取它并将其绘制到您的设置中，如下所示：

```py
# myproject/settings/_base.py
LAST_FM_API_KEY = get_secret("LAST_FM_API_KEY")
```

1.  还要使用以下命令在虚拟环境中安装`requests`库：

```py
(env)$ pip install requests==2.22.0
```

1.  让我们来看看用于热门 indie 曲目的 JSON 端点的结构（`https://ws.audioscrobbler.com/2.0/?method=tag.gettoptracks&tag=indie&api_key=YOUR_API_KEY&format=json`），它应该看起来像这样：

```py
{
  "tracks": {
    "track": [
      {
        "name": "Mr. Brightside",
        "duration": "224",
        "mbid": "37d516ab-d61f-4bcb-9316-7a0b3eb845a8",
        "url": "https://www.last.fm/music
         /The+Killers/_/Mr.+Brightside",
        "streamable": {
          "#text": "0",
          "fulltrack": "0"
        },
        "artist": {
          "name": "The Killers",
          "mbid": "95e1ead9-4d31-4808-a7ac-32c3614c116b",
          "url": "https://www.last.fm/music/The+Killers"
        },
        "image": [
          {
            "#text": 
            "https://lastfm.freetls.fastly.net/i/u/34s
             /2a96cbd8b46e442fc41c2b86b821562f.png",
            "size": "small"
          },
          {
            "#text":  
           "https://lastfm.freetls.fastly.net/i/u/64s
            /2a96cbd8b46e442fc41c2b86b821562f.png",
            "size": "medium"
          },
          {
            "#text": 
            "https://lastfm.freetls.fastly.net/i/u/174s
             /2a96cbd8b46e442fc41c2b86b821562f.png",
            "size": "large"
          },
          {
            "#text": 
            "https://lastfm.freetls.fastly.net/i/u/300x300
             /2a96cbd8b46e442fc41c2b86b821562f.png",
            "size": "extralarge"
          }
        ],
        "@attr": {
          "rank": "1"
        }
      },
      ...
    ],
    "@attr": {
      "tag": "indie",
      "page": "1",
      "perPage": "50",
      "totalPages": "4475",
      "total": "223728"
    }
  }
}
```

我们想要读取曲目的`名称`、`艺术家`、`URL`和中等大小的图像。此外，我们对总共有多少页感兴趣，这是在 JSON 文件的末尾作为元信息提供的。

# 如何做...

按照以下步骤创建一个`Song`模型和一个管理命令，该命令以 JSON 格式将[Last.fm](http://last.fm)的热门曲目导入到数据库中：

1.  如果尚未这样做，在`music`应用程序中，创建一个`management`目录，然后在其中创建一个`commands`子目录。在这两个新目录中添加空的`__init__.py`文件，使它们成为 Python 包。

1.  添加一个`import_music_from_lastfm_json.py`文件，内容如下：

```py
# myproject/apps/music/management/commands
# /import_music_from_lastfm_json.py
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = "Imports top songs from last.fm as JSON."
    SILENT, NORMAL, VERBOSE, VERY_VERBOSE = 0, 1, 2, 3
    API_URL = "https://ws.audioscrobbler.com/2.0/"

    def add_arguments(self, parser):
        # Named (optional) arguments
        parser.add_argument("--max_pages", type=int, default=0)

    def handle(self, *args, **options):
        self.verbosity = options.get("verbosity", self.NORMAL)
        self.max_pages = options["max_pages"]
        self.prepare()
        self.main()
        self.finalize()
```

1.  然后，在`Command`类的同一文件中，创建一个`prepare()`方法：

```py
    def prepare(self):
        from django.conf import settings

        self.imported_counter = 0
        self.skipped_counter = 0
        self.params = {
            "method": "tag.gettoptracks",
            "tag": "indie",
            "api_key": settings.LAST_FM_API_KEY,
            "format": "json",
            "page": 1,
        }
```

1.  然后，在那里创建`main()`方法：

```py
    def main(self):
        import requests

        response = requests.get(self.API_URL, params=self.params)
        if response.status_code != requests.codes.ok:
            self.stderr.write(f"Error connecting to 
             {response.url}")
            return
        response_dict = response.json()
        pages = int(
            response_dict.get("tracks", {})
            .get("@attr", {}).get("totalPages", 1)
        )

        if self.max_pages > 0:
            pages = min(pages, self.max_pages)

        if self.verbosity >= self.NORMAL:
            self.stdout.write(f"=== Importing {pages} page(s) 
             of tracks ===")

        self.save_page(response_dict)

        for page_number in range(2, pages + 1):
            self.params["page"] = page_number
            response = requests.get(self.API_URL, 
            params=self.params)
            if response.status_code != requests.codes.ok:
                self.stderr.write(f"Error connecting to 
                 {response.url}")
                return
            response_dict = response.json()
            self.save_page(response_dict)
```

1.  分页源的每一页将由我们应该创建的`save_page()`方法保存，如下所示：

```py
    def save_page(self, data):
        import os
        import requests
        from io import BytesIO
        from django.core.files import File
        from ...forms import SongForm

        for track_dict in data.get("tracks", {}).get("track"):
            if not track_dict:
                continue

            song_dict = {
                "artist": track_dict.get("artist", {}).get("name", ""),
                "title": track_dict.get("name", ""),
                "url": track_dict.get("url", ""),
            }
            form = SongForm(data=song_dict)
            if form.is_valid():
                song = form.save()

                image_dict = track_dict.get("image", None)
                if image_dict:
                    image_url = image_dict[1]["#text"]
                    image_response = requests.get(image_url)
                    song.image.save(
 os.path.basename(image_url),
 File(BytesIO(image_response.content)),
 )

                if self.verbosity >= self.NORMAL:
                    self.stdout.write(f" - {song}\n")
                self.imported_counter += 1
            else:
                if self.verbosity >= self.NORMAL:
                    self.stderr.write(
                        f"Errors importing song "
                        f"{song_dict['artist']} - 
                         {song_dict['title']}:\n"
                    )
                    self.stderr.write(f"{form.errors.as_json()}\n")
                self.skipped_counter += 1
```

1.  我们将使用`finalize()`方法完成类：

```py
    def finalize(self):
        if self.verbosity >= self.NORMAL:
            self.stdout.write(f"-------------------------\n")
            self.stdout.write(f"Songs imported: 
             {self.imported_counter}\n")
            self.stdout.write(f"Songs skipped: 
             {self.skipped_counter}\n\n")
```

1.  要运行导入，请在命令行中调用以下命令：

```py
(env)$ python manage.py import_music_from_lastfm_json --max_pages=3
```

# 它是如何工作的...

如前所述，脚本的参数可以是**位置**的，如果它们只列出一系列字符串，或者**命名**的，如果它们以`--`和变量名开头。命名的`--max_pages`参数将导入的数据限制为三页。如果要下载所有可用的热门曲目，请跳过它，或者明确传递 0（零）。

请注意，`totalPages`值中详细说明了大约有 4,500 页，这将需要很长时间和大量处理。

我们的脚本结构与以前的导入脚本类似：

+   `prepare()`方法用于设置

+   `main()`方法处理请求并处理响应

+   `save_page()`方法保存单个分页页面的歌曲

+   `finalize()`方法打印出导入统计信息

在`main()`方法中，我们使用`requests.get()`来读取来自[Last.fm](http://last.fm)的数据，传递`params`查询参数。响应对象具有名为`json()`的内置方法，它将 JSON 字符串转换为解析后的字典对象。从第一个请求中，我们了解到总页数，然后读取每一页并调用`save_page()`方法来解析信息并保存歌曲。

在`save_page()`方法中，我们从曲目中读取值并构建模型表单所需的字典。我们验证表单。如果数据有效，则创建`Song`对象。

导入的一个有趣部分是下载和保存图像。在这里，我们还使用`requests.get()`来检索图像数据，然后我们通过`BytesIO`将其传递给`File`，这将相应地在`image.save()`方法中使用。 `image.save()`的第一个参数是一个文件名，无论如何都将被`upload_to`函数的值覆盖，并且仅对于文件扩展名是必需的。

如果使用`--verbosity=1`或更高的命令调用，我们将看到有关导入的详细信息，就像在以前的食谱中一样。

您可以在[`www.last.fm/api/`](https://www.last.fm/api/)了解有关如何使用[Last.fm](http://last.fm)的更多信息。

# 另请参阅

+   *从本地 CSV 文件导入数据*食谱

+   *从本地 Excel 文件导入数据*食谱

+   *从外部 XML 文件导入数据*食谱

# 从外部 XML 文件导入数据

正如我们在前面的食谱中展示的可以使用 JSON 做的事情一样，[Last.fm](http://last.fm)文件还允许您以 XML 格式从其服务中获取数据。在这个食谱中，我们将向您展示如何做到这一点。

# 准备工作

按照以下步骤从[Last.fm](http://last.fm)导入 XML 格式的数据：

1.  让我们从我们在*从本地 CSV 文件导入数据*食谱中创建的`music`应用程序开始。

1.  要使用[Last.fm](http://last.fm)，您需要注册并获取 API 密钥。 API 密钥可以是

在[`www.last.fm/api/account/create`](https://www.last.fm/api/account/create)创建

1.  API 密钥必须在设置中设置为`LAST_FM_API_KEY`。我们建议

提供它来自秘密文件或环境变量，并将其绘制到您的设置中，如下所示：

```py
# myproject/settings/_base.py
LAST_FM_API_KEY = get_secret("LAST_FM_API_KEY")
```

1.  还要使用以下命令在虚拟环境中安装`requests`和`defusedxml`库：

```py
(env)$ pip install requests==2.22.0
(env)$ pip install defusedxml==0.6.0

```

1.  让我们检查顶级独立曲目的 JSON 端点的结构（`https://ws.audioscrobbler.com/2.0/?method=tag.gettoptracks&tag=indie&api_key=YOUR_API_KEY&format=xml`），应该看起来像这样：

```py
<?xml version="1.0" encoding="UTF-8" ?>
<lfm status="ok">
    <tracks tag="indie" page="1" perPage="50" 
 totalPages="4475" total="223728">
        <track rank="1">
            <name>Mr. Brightside</name>
            <duration>224</duration>
            <mbid>37d516ab-d61f-4bcb-9316-7a0b3eb845a8</mbid>
            <url>https://www.last.fm/music
            /The+Killers/_/Mr.+Brightside</url>
            <streamable fulltrack="0">0</streamable>
            <artist>
                <name>The Killers</name>
                <mbid>95e1ead9-4d31-4808-a7ac-32c3614c116b</mbid>
                <url>https://www.last.fm/music/The+Killers</url>
            </artist>
            <image size="small">https://lastfm.freetls.fastly.net/i
             /u/34s/2a96cbd8b46e442fc41c2b86b821562f.png</image>
            <image size="medium">
            https://lastfm.freetls.fastly.net/i
            /u/64s/2a96cbd8b46e442fc41c2b86b821562f.png</image>
            <image size="large">https://lastfm.freetls.fastly.net/i
            /u/174s/2a96cbd8b46e442fc41c2b86b821562f.png</image>
            <image size="extralarge">
                https://lastfm.freetls.fastly.net/i/u/300x300
                /2a96cbd8b46e442fc41c2b86b821562f.png
            </image>
        </track>
        ...
    </tracks>
</lfm>
```

# 如何做...

按照以下步骤创建`Song`模型和一个管理命令，该命令以 XML 格式将顶级曲目从[Last.fm](http://last.fm)导入到数据库中：

1.  如果尚未这样做，请在`music`应用程序中创建一个`management`目录，然后在其中创建一个`commands`子目录。在两个新目录中都添加空的`__init__.py`文件，使它们成为 Python 包。

1.  添加一个名为`import_music_from_lastfm_xml.py`的文件，其中包含以下内容：

```py
# myproject/apps/music/management/commands
# /import_music_from_lastfm_xml.py
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = "Imports top songs from last.fm as XML."
    SILENT, NORMAL, VERBOSE, VERY_VERBOSE = 0, 1, 2, 3
    API_URL = "https://ws.audioscrobbler.com/2.0/"

    def add_arguments(self, parser):
        # Named (optional) arguments
        parser.add_argument("--max_pages", type=int, default=0)

    def handle(self, *args, **options):
        self.verbosity = options.get("verbosity", self.NORMAL)
        self.max_pages = options["max_pages"]
        self.prepare()
        self.main()
        self.finalize()
```

1.  然后，在`Command`类的同一文件中，创建一个`prepare()`方法： 

```py
    def prepare(self):
        from django.conf import settings

        self.imported_counter = 0
        self.skipped_counter = 0
        self.params = {
            "method": "tag.gettoptracks",
            "tag": "indie",
            "api_key": settings.LAST_FM_API_KEY,
            "format": "xml",
            "page": 1,
        }
```

1.  然后，在那里创建`main()`方法：

```py
    def main(self):
        import requests
        from defusedxml import ElementTree

        response = requests.get(self.API_URL, params=self.params)
        if response.status_code != requests.codes.ok:
            self.stderr.write(f"Error connecting to {response.url}")
            return
        root = ElementTree.fromstring(response.content)

        pages = int(root.find("tracks").attrib.get("totalPages", 1))
        if self.max_pages > 0:
            pages = min(pages, self.max_pages)

        if self.verbosity >= self.NORMAL:
            self.stdout.write(f"=== Importing {pages} page(s) 
             of songs ===")

        self.save_page(root)

        for page_number in range(2, pages + 1):
            self.params["page"] = page_number
            response = requests.get(self.API_URL, params=self.params)
            if response.status_code != requests.codes.ok:
                self.stderr.write(f"Error connecting to {response.url}")
                return
            root = ElementTree.fromstring(response.content)
            self.save_page(root)
```

1.  分页源的每个页面将由我们应该创建的`save_page()`方法保存，如下所示：

```py
    def save_page(self, root):
        import os
        import requests
        from io import BytesIO
        from django.core.files import File
        from ...forms import SongForm

        for track_node in root.findall("tracks/track"):
            if not track_node:
                continue

            song_dict = {
                "artist": track_node.find("artist/name").text,
                "title": track_node.find("name").text,
                "url": track_node.find("url").text,
            }
            form = SongForm(data=song_dict)
            if form.is_valid():
                song = form.save()

                image_node = track_node.find("image[@size='medium']")
                if image_node is not None:
                    image_url = image_node.text
                    image_response = requests.get(image_url)
                    song.image.save(
 os.path.basename(image_url),
 File(BytesIO(image_response.content)),
 )

                if self.verbosity >= self.NORMAL:
                    self.stdout.write(f" - {song}\n")
                self.imported_counter += 1
            else:
                if self.verbosity >= self.NORMAL:
                    self.stderr.write(
                        f"Errors importing song "
                        f"{song_dict['artist']} - {song_dict['title']}:\n"
                    )
                    self.stderr.write(f"{form.errors.as_json()}\n")
                self.skipped_counter += 1
```

1.  我们将使用`finalize()`方法完成课程：

```py
    def finalize(self):
        if self.verbosity >= self.NORMAL:
            self.stdout.write(f"-------------------------\n")
            self.stdout.write(f"Songs imported: {self.imported_counter}\n")
            self.stdout.write(f"Songs skipped: {self.skipped_counter}\n\n")
```

1.  要运行导入，请在命令行中调用以下内容：

```py
(env)$ python manage.py import_music_from_lastfm_xml --max_pages=3
```

# 它是如何工作的...

该过程类似于 JSON 方法。使用`requests.get()`方法，我们从[Last.fm](http://last.fm)读取数据，将查询参数作为`params`传递。响应的 XML 内容传递给`defusedxml`模块的`ElementTree`解析器，并返回`root`节点。

`defusedxml`模块是`xml`模块的更安全的替代品。它可以防止 XML 炸弹——一种允许攻击者使用几百字节的 XML 数据占用几 GB 内存的漏洞。

`ElementTree`节点具有`find()`和`findall()`方法，您可以通过这些方法传递`XPath`查询来过滤特定的子节点。

以下是`ElementTree`支持的可用 XPath 语法表：

| **XPath 语法组件** | **含义** |
| --- | --- |
| `tag` | 这会选择具有给定标签的所有子元素。 |
| `*` | 这会选择所有子元素。 |
| `.` | 这会选择当前节点。 |
| `//` | 这会选择当前元素下所有级别的所有子元素。 |
| `..` | 这会选择父元素。 |
| `[@attrib]` | 这会选择具有给定属性的所有元素。 |
| `[@attrib='value']` | 这会选择具有给定值的给定属性的所有元素。 |
| `[tag]` | 这会选择具有名为 tag 的子元素的所有元素。仅支持直接子元素。 |
| `[position]` | 这会选择位于给定位置的所有元素。位置可以是整数（`1`是第一个位置），`last()`表达式（用于最后位置），或相对于最后位置的位置（例如，`last()-1`）。 |

因此，在`main()`方法中，使用`root.find("tracks").attrib.get("totalPages", 1)`，我们读取页面的总数，如果数据不完整，则默认为 1。我们将保存第一页，然后逐个保存其他页面。

在`save_page()`方法中，`root.findall("tracks/track")`返回一个迭代器，通过`<tracks>`节点下的`<track>`节点。使用`track_node.find("image[@size='medium']")`，我们获得中等大小的图像。同样，`Song`的创建是通过用于验证传入数据的模型表单完成的。

如果我们使用`--verbosity=1`或更高的命令调用，我们将看到有关导入歌曲的详细信息，就像在以前的食谱中一样。

# 还有更多...

您可以从以下链接了解更多信息：

+   阅读如何在[Last.fm](http://last.fm)上使用[`www.last.fm/api/`](https://www.last.fm/api/)。

+   在[`en.wikipedia.org/wiki/XPath`](https://en.wikipedia.org/wiki/XPath)上阅读有关 XPath 的信息。

+   可以在[`docs.python.org/3/library/xml.etree.elementtree.html`](https://docs.python.org/3/library/xml.etree.elementtree.html)找到`ElementTree`的完整文档。

# 另请参阅

+   *从本地 CSV 文件导入数据*食谱

+   *从本地 Excel 文件导入数据*食谱

+   *从外部 JSON 文件导入数据*食谱

# 为搜索引擎准备分页站点地图

**站点地图**协议告诉搜索引擎有关网站上所有不同页面的信息。通常，它是一个单一的`sitemap.xml`文件，通知可以被索引以及频率。如果您的网站上有很多不同的页面，您还可以拆分和分页 XML 文件，以更快地呈现每个资源列表。

在这个食谱中，我们将向您展示如何创建一个分页站点地图，以在您的 Django 网站中使用。

# 准备工作

对于这个和其他食谱，我们需要扩展`music`应用程序并在那里添加列表和详细视图：

1.  创建具有以下内容的`views.py`文件：

```py
# myproject/apps/music/views.py
from django.views.generic import ListView, DetailView
from django.utils.translation import ugettext_lazy as _
from .models import Song

class SongList(ListView):
    model = Song

class SongDetail(DetailView):
    model = Song
```

1.  创建具有以下内容的`urls.py`文件：

```py
# myproject/apps/music/urls.py
from django.urls import path
from .views import SongList, SongDetail

app_name = "music"

urlpatterns = [
    path("", SongList.as_view(), name="song_list"),
    path("<uuid:pk>/", SongDetail.as_view(), name="song_detail"),
]
```

1.  将该 URL 配置包含到项目的 URL 配置中：

```py
# myproject/urls.py
from django.conf.urls.i18n import i18n_patterns
from django.urls import include, path

urlpatterns = i18n_patterns(
    # …
 path("songs/", include("myproject.apps.music.urls", 
     namespace="music")),
)
```

1.  为歌曲列表视图创建一个模板：

```py
{# music/song_list.html #}
{% extends "base.html" %}
{% load i18n %}

{% block main %}
    <ul>
        {% for song in object_list %}
            <li><a href="{{ song.get_url_path }}">
             {{ song }}</a></li>
        {% endfor %}
    </ul>
{% endblock %}
```

1.  然后，为歌曲详细视图创建一个：

```py
{# music/song_detail.html #}
{% extends "base.html" %}
{% load i18n %}

{% block content %}
    {% with song=object %}
        <h1>{{ song }}</h1>
        {% if song.image %}
            <img src="img/{{ song.image.url }}" alt="{{ song }}" />
        {% endif %}
        {% if song.url %}
            <a href="{{ song.url }}" target="_blank" 
             rel="noreferrer noopener">
                {% trans "Check this song" %}
            </a>
        {% endif %}
    {% endwith %}
{% endblock %}
```

# 如何做...

要添加分页网站地图，请按照以下步骤操作：

1.  在设置中的`INSTALLED_APPS`中包含`django.contrib.sitemaps`：

```py
# myproject/settings/_base.py
INSTALLED_APPS = [
    # …
    "django.contrib.sitemaps",
    # …
]
```

1.  根据以下方式修改项目的`urls.py`：

```py
# myproject/urls.py
from django.conf.urls.i18n import i18n_patterns
from django.urls import include, path
from django.contrib.sitemaps import views as sitemaps_views
from django.contrib.sitemaps import GenericSitemap
from myproject.apps.music.models import Song

class MySitemap(GenericSitemap):
 limit = 50

 def location(self, obj):
 return obj.get_url_path()

song_info_dict = {
 "queryset": Song.objects.all(), 
 "date_field": "modified",
}
sitemaps = {"music": MySitemap(song_info_dict, priority=1.0)}

urlpatterns = [
 path("sitemap.xml", sitemaps_views.index, 
     {"sitemaps": sitemaps}),
 path("sitemap-<str:section>.xml", sitemaps_views.sitemap, 
     {"sitemaps": sitemaps},
 name="django.contrib.sitemaps.views.sitemap"
    ),
]

urlpatterns += i18n_patterns(
    # …
    path("songs/", include("myproject.apps.music.urls", 
     namespace="music")),
)
```

# 它是如何工作的...

如果您查看`http://127.0.0.1:8000/sitemap.xml`，您将看到带有分页网站地图的索引：

```py
<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <sitemap>
        <loc>http://127.0.0.1:8000/sitemap-music.xml</loc>
    </sitemap>
    <sitemap>
        <loc>http://127.0.0.1:8000/sitemap-music.xml?p=2</loc>
    </sitemap>
    <sitemap>
        <loc>http://127.0.0.1:8000/sitemap-music.xml?p=3</loc>
    </sitemap>
</sitemapindex>

```

每个页面将显示最多 50 个条目，带有 URL、最后修改时间和优先级：

```py
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>http://127.0.0.1:8000/en/songs/b2d3627b-dbc7
         -4c11-a13e-03d86f32a719/</loc>
        <lastmod>2019-12-15</lastmod>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>http://127.0.0.1:8000/en/songs/f5c386fd-1952
         -4ace-9848-717d27186fa9/</loc>
        <lastmod>2019-12-15</lastmod>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>http://127.0.0.1:8000/en/songs/a59cbb5a-16e8
         -46dd-9498-d86e24e277a5/</loc>
        <lastmod>2019-12-15</lastmod>
        <priority>1.0</priority>
    </url>
    ...
</urlset>
```

当您的网站准备就绪并发布到生产环境时，您可以使用网站地图框架提供的`ping_google`管理命令通知**Google 搜索引擎**有关您的页面。在生产服务器上执行以下命令：

```py
(env)$ python manage.py ping_google --settings=myproject.settings.production
```

# 还有更多...

您可以从以下链接了解更多信息：

+   在[这里](https://www.sitemaps.org/)阅读有关网站地图协议的信息。

+   在[这里](https://docs.djangoproject.com/en/3.0/ref/contrib/sitemaps/)阅读有关 Django 网站地图框架的更多信息

[`docs.djangoproject.com/en/3.0/ref/contrib/sitemaps/`](https://docs.djangoproject.com/en/3.0/ref/contrib/sitemaps/)

# 另请参阅

+   *创建可过滤的 RSS 订阅*示例

# 创建可过滤的 RSS 订阅

Django 带有一个**聚合源框架**，允许您创建**真正简单的聚合**（**RSS**）和**Atom**源。RSS 和 Atom 源是具有特定语义的 XML 文档。它们可以订阅到 RSS 阅读器，如 Feedly，或者它们可以在其他网站、移动应用程序或桌面应用程序中进行聚合。在这个示例中，我们将创建一个提供有关歌曲信息的 RSS 源。此外，结果将可以通过 URL 查询参数进行过滤。

# 准备工作

首先，根据*从本地 CSV 文件导入数据*和*为搜索引擎准备分页网站地图*的步骤创建`music`应用程序。具体来说，请按照*准备工作*部分中的步骤设置模型、表单、视图、URL 配置和模板。

对于列出歌曲的视图，我们将添加按艺术家过滤的功能，稍后 RSS 订阅也将使用该功能：

1.  在`forms.py`中添加一个过滤表单。它将具有`artist`选择字段，其中所有艺术家名称都按字母顺序排序，忽略大小写：

```py
# myproject/apps/music/forms.py
from django import forms
from django.utils.translation import ugettext_lazy as _
from .models import Song

# …

class SongFilterForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        artist_choices = [
            (artist, artist)
            for artist in sorted(
                Song.objects.values_list("artist", 
                 flat=True).distinct(),
                key=str.casefold
            )
        ]
        self.fields["artist"] = forms.ChoiceField(
 label=_("Artist"),
 choices=artist_choices,
 required=False,
 )
```

1.  使用方法增强`SongList`视图来管理过滤：`get()`方法将处理过滤并显示结果，`get_form_kwargs()`方法将为过滤表单准备关键字参数，`get_queryset()`方法将按艺术家过滤歌曲：

```py
# myproject/apps/music/views.py
from django.http import Http404
from django.views.generic import ListView, DetailView, FormView
from django.utils.translation import ugettext_lazy as _
from .models import Song
from .forms import SongFilterForm

class SongList(ListView, FormView):
    form_class = SongFilterForm
    model = Song

    def get(self, request, *args, **kwargs):
        form_class = self.get_form_class()
        self.form = self.get_form(form_class)

        self.object_list = self.get_queryset()
        allow_empty = self.get_allow_empty()
        if not allow_empty and len(self.object_list) == 0:
            raise Http404(_(u"Empty list and '%(class_name)s
             .allow_empty' is False.")
                          % {'class_name': 
                           self.__class__.__name__})

        context = self.get_context_data(object_list=
         self.object_list, form=self.form)
        return self.render_to_response(context)

    def get_form_kwargs(self):
        kwargs = {
            'initial': self.get_initial(),
            'prefix': self.get_prefix(),
        }
        if self.request.method == 'GET':
            kwargs.update({
                'data': self.request.GET,
            })
        return kwargs

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.form.is_valid():
            artist = self.form.cleaned_data.get("artist")
            if artist:
                queryset = queryset.filter(artist=artist)
        return queryset
```

1.  修改歌曲列表模板以添加过滤表单：

```py
{# music/song_list.html #}
{% extends "base.html" %}
{% load i18n %}

{% block sidebar %}
 <form action="" method="get">
 {{ form.errors }}
 {{ form.as_p }}
 <button type="submit" class="btn btn-primary">
         {% trans "Filter" %}</button>
 </form>
{% endblock %}

{% block main %}
    <ul>
        {% for song in object_list %}
            <li><a href="{{ song.get_url_path }}">
             {{ song }}</a></li>
        {% endfor %}
    </ul>
{% endblock %}
```

如果您现在在浏览器中检查歌曲列表视图并按照，比如说，Lana Del Rey 进行歌曲过滤，您将看到以下结果：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/cfefc603-0bcb-4f52-9c22-eceda7cd8df6.png)

过滤后的歌曲列表的 URL 将是`http://127.0.0.1:8000/en/songs/?artist=Lana+Del+Rey`。

# 如何做...

现在，我们将向音乐应用程序添加 RSS 订阅：

1.  在`music`应用程序中，创建`feeds.py`文件并添加以下内容：

```py
# myproject/apps/music/feeds.py
from django.contrib.syndication.views import Feed
from django.urls import reverse

from .models import Song
from .forms import SongFilterForm

class SongFeed(Feed):
    description_template = "music/feeds/song_description.html"

    def get_object(self, request, *args, **kwargs):
        form = SongFilterForm(data=request.GET)
        obj = {}
        if form.is_valid():
            obj = {"query_string": request.META["QUERY_STRING"]}
            for field in ["artist"]:
                value = form.cleaned_data[field]
                obj[field] = value
        return obj

    def title(self, obj):
        the_title = "Music"
        artist = obj.get("artist")
        if artist:
            the_title = f"Music by {artist}"
        return the_title

    def link(self, obj):
        return self.get_named_url("music:song_list", obj)

    def feed_url(self, obj):
        return self.get_named_url("music:song_rss", obj)

    @staticmethod
    def get_named_url(name, obj):
        url = reverse(name)
        qs = obj.get("query_string", False)
        if qs:
            url = f"{url}?{qs}"
        return url

    def items(self, obj):
        queryset = Song.objects.order_by("-created")

        artist = obj.get("artist")
        if artist:
            queryset = queryset.filter(artist=artist)

        return queryset[:30]

    def item_pubdate(self, item):
        return item.created
```

1.  为 RSS 源中的歌曲描述创建一个模板：

```py
{# music/feeds/song_description.html #}
{% load i18n %}
{% with song=obj %}
    {% if song.image %}
        <img src="img/{{ song.image.url }}" alt="{{ song }}" />
    {% endif %}
    {% if song.url %}
        <a href="{{ song.url }}" target="_blank" 
         rel="noreferrer noopener">
            {% trans "Check this song" %}
        </a>
    {% endif %}
{% endwith %}
```

1.  在应用程序的 URL 配置中插入 RSS 源：

```py
# myproject/apps/music/urls.py
from django.urls import path

from .feeds import SongFeed
from .views import SongList, SongDetail

app_name = "music"

urlpatterns = [
    path("", SongList.as_view(), name="song_list"),
    path("<uuid:pk>/", SongDetail.as_view(), name="song_detail"),
 path("rss/", SongFeed(), name="song_rss"),
]
```

1.  在歌曲列表视图的模板中，添加到 RSS 源的链接：

```py
{# music/song_list.html #} 
{% url "music:songs_rss" as songs_rss_url %}
<p>
    <a href="{{ songs_rss_url }}?{{ request.META.QUERY_STRING }}">
        {% trans "Subscribe to RSS feed" %}
    </a>
</p> 
```

# 它是如何工作的...

如果您刷新`http://127.0.0.1:8000/en/songs/?artist=Lana+Del+Rey`上的过滤列表视图，您将看到指向`http://127.0.0.1:8000/en/songs/rss/?artist=Lana+Del+Rey`的订阅 RSS 订阅链接。这将是按艺术家筛选的最多 30 首歌曲的 RSS 订阅。

`SongFeed`类负责自动生成 RSS 源的 XML 标记。我们在那里指定了以下方法：

+   `get_object()`方法为`Feed`类定义了上下文字典，其他方法将使用它。

+   `title()`方法根据结果是否被过滤定义了源的标题。

+   `link()`方法返回列表视图的 URL，而`feed_url()`返回订阅的 URL。它们都使用一个辅助方法`get_named_url()`，该方法通过路径名和查询参数形成 URL。

+   `items()`方法返回歌曲的`queryset`，可以按艺术家进行筛选。

+   `item_pubdate()`方法返回歌曲的创建日期。

要查看我们正在扩展的`Feed`类的所有可用方法和属性，请参阅以下文档：[`docs.djangoproject.com/en/3.0/ref/contrib/syndication/#feed-class-reference`](https://docs.djangoproject.com/en/3.0/ref/contrib/syndication/#feed-class-reference)。

# 另请参阅

+   *从本地 CSV 文件导入数据*示例

+   *为搜索引擎准备分页站点地图*示例

# 使用 Django REST 框架创建 API

当您需要为您的模型创建 RESTful API 以便与第三方传输数据时，**Django REST 框架**可能是您可以使用的最佳工具。该框架有广泛的文档和基于 Django 的实现，有助于使其更易于维护。在这个示例中，您将学习如何使用 Django REST 框架，以允许您的项目合作伙伴、移动客户端或基于 Ajax 的网站访问您网站上的数据，以适当地创建、读取、更新和删除内容。

# 准备工作

首先，在虚拟环境中使用以下命令安装 Django REST 框架：

```py
(env)$ pip install djangorestframework==3.11.0
```

在设置的`INSTALLED_APPS`中添加`"rest_framework"`。

然后，增强我们在*从本地 CSV 文件导入数据*示例中定义的`music`应用程序。您还希望收集 Django REST 框架提供的静态文件，以使其提供的页面样式尽可能漂亮：

```py
(env)$ python manage.py collectstatic
```

# 如何做...

要在我们的`music`应用程序中集成新的 RESTful API，请执行以下步骤：

1.  在设置中为 Django REST 框架添加配置，如下所示：

```py
# myproject/settings/_base.py
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [ "rest_framework.permissions
         .DjangoModelPermissionsOrAnonReadOnly"
    ],
    "DEFAULT_PAGINATION_CLASS": 
    "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 50,
}
```

1.  在`music`应用程序中，创建`serializers.py`文件，内容如下：

```py
from rest_framework import serializers
from .models import Song

class SongSerializer(serializers.ModelSerializer):
    class Meta:
        model = Song
        fields = ["uuid", "artist", "title", "url", "image"]
```

1.  在`music`应用程序的`views.py`文件中添加两个基于类的视图：

```py
from rest_framework import generics

from .serializers import SongSerializer
from .models import Song

# …

class RESTSongList(generics.ListCreateAPIView):
    queryset = Song.objects.all()
    serializer_class = SongSerializer

    def get_view_name(self):
        return "Song List"

class RESTSongDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Song.objects.all()
    serializer_class = SongSerializer

    def get_view_name(self):
        return "Song Detail"
```

1.  最后，将新视图插入到项目 URL 配置中：

```py
# myproject/urls.py
from django.urls import include, path
from myproject.apps.music.views import RESTSongList, RESTSongDetail

urlpatterns = [
    path("api-auth/", include("rest_framework.urls", 
     namespace="rest_framework")),
    path("rest-api/songs/", RESTSongList.as_view(), 
     name="rest_song_list"),
    path(
        "rest-api/songs/<uuid:pk>/", RESTSongDetail.as_view(), 
          name="rest_song_detail"
    ),
    # …
]
```

# 工作原理...

我们在这里创建的是一个音乐 API，您可以阅读分页的歌曲列表，创建新歌曲，并通过 ID 阅读、更改或删除单个歌曲。阅读是允许的，无需身份验证，但是您必须拥有具有适当权限的用户帐户才能添加、更改或删除歌曲。Django REST 框架为您提供基于 Web 的 API 文档，当您通过`GET`在浏览器中访问 API 端点时会显示出来。未登录时，框架会显示类似以下内容：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/cd2daa28-8624-4711-a718-076ef523be69.png)

以下是您可以使用创建的 API 的方法：

| **URL** | **HTTP 方法** | **描述** |
| --- | --- | --- |
| `/rest-api/songs/` | `GET` | 按 50 页列出歌曲。 |
| `/rest-api/songs/` | `POST` | 如果请求的用户经过身份验证并被授权创建歌曲，则创建新歌曲。 |
| `/rest-api/songs/b328109b-``5ec0-4124-b6a9-e963c62d212c/` | `GET` | 获取 ID 为`b328109b-5ec0-4124-b6a9-e963c62d212c`的歌曲。 |
| `/rest-api/songs/b328109b-``5ec0-4124-b6a9-e963c62d212c/` | `PUT` | 如果用户经过身份验证并被授权更改歌曲，则更新 ID 为`b328109b-5ec0-4124-b6a9-e963c62d212c`的歌曲。 |
| `/rest-api/songs/b328109b-``5ec0-4124-b6a9-e963c62d212c/` | `DELETE` | 如果用户经过身份验证并被授权删除歌曲，则删除 ID 为`b328109b-5ec0-4124-b6a9-e963c62d212c`的歌曲。 |

您可能会问如何实际使用 API。例如，我们可以使用`requests`库从 Python 脚本中创建新歌曲，如下所示：

```py
import requests

response = requests.post(
    url="http://127.0.0.1:8000/rest-api/songs/",
    data={
        "artist": "Luwten",
        "title": "Go Honey",
    },
    auth=("admin", "<YOUR_ADMIN_PASSWORD>"),
)
assert(response.status_code == requests.codes.CREATED)
```

也可以通过**Postman**应用程序来实现，该应用程序提供了一个用户友好的界面来提交请求，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/0605f718-271f-428b-a134-5e1a8cbbe6a9.png)

当登录时，您还可以通过框架生成的 API 文档下的集成表单尝试 API，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/63df3efe-5bfc-4179-9916-e2c4fd7aada4.png)

让我们快速看一下我们编写的代码是如何工作的。在设置中，我们已经设置了访问权限取决于 Django 系统的权限。对于匿名请求，只允许阅读。其他访问选项包括允许任何用户拥有任何权限，只允许经过身份验证的用户拥有任何权限，允许工作人员用户拥有任何权限等等。完整列表可以在[`www.django-rest-framework.org/api-guide/permissions/`](https://www.django-rest-framework.org/api-guide/permissions/)上找到。

然后，在设置中，设置了分页。当前选项是将限制和偏移参数设置为 SQL 查询中的参数。其他选项是对静态内容使用页面编号进行分页，或者对实时数据使用游标分页。我们将默认分页设置为每页 50 个项目。

稍后，我们为歌曲定义了一个序列化程序。它控制将显示在输出中的数据并验证输入。在 Django REST 框架中，有各种序列化关系的方法，我们在示例中选择了最冗长的方法。

要了解如何序列化关系，请参阅[`www.django-rest-framework.org/api-guide/relations/`](https://www.django-rest-framework.org/api-guide/relations/)上的文档。

在定义了序列化程序之后，我们创建了两个基于类的视图来处理 API 端点，并将它们插入到 URL 配置中。在 URL 配置中，我们还有一个规则（`/api-auth/`）用于可浏览的 API 页面，登录和注销。

# 另请参阅

+   *为搜索引擎准备分页站点地图*食谱

+   *创建可过滤的 RSS 提要*食谱

+   在第十一章*，测试*中的*使用 Django REST 框架创建的 API 进行测试*食谱


# 第十章：花里胡哨

在本章中，我们将涵盖以下主题：

+   使用 Django shell

+   使用数据库查询表达式

+   为了更好地支持国际化，对`slugify()`函数进行猴子补丁

+   切换调试工具栏

+   使用 ThreadLocalMiddleware

+   使用信号通知管理员有关新条目的信息

+   检查缺少的设置

# 介绍

在本章中，我们将介绍一些重要的要点，这些要点将帮助您更好地理解和利用 Django。我们将概述如何使用 Django shell 在编写文件之前对代码进行实验。您将了解到猴子补丁，也称为游击补丁，这是 Python 和 Ruby 等动态语言的强大功能。我们还将讨论全文搜索功能，并学习如何调试代码并检查其性能。然后，您将学习如何从任何模块中访问当前登录的用户（以及其他请求参数）。您还将学习如何处理信号并创建系统检查。准备好迎接有趣的编程体验！

# 技术要求

要使用本章的代码，您需要最新稳定版本的 Python、MySQL 或 PostgreSQL 数据库以及一个带有虚拟环境的 Django 项目。

您可以在 GitHub 存储库的`ch10`目录中找到本章的所有代码，网址为[`github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition`](https://github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition)。

# 使用 Django shell

在激活虚拟环境并选择项目目录作为当前目录后，在命令行工具中输入以下命令：

```py
(env)$ python manage.py shell
```

通过执行上述命令，您将进入一个交互式的 Python shell，为您的 Django 项目进行配置，在那里您可以玩弄代码，检查类，尝试方法或即时执行脚本。在本教程中，我们将介绍您在使用 Django shell 时需要了解的最重要的功能。

# 准备工作

您可以安装**IPython**或**bpython**，以为 Python shell 提供额外的接口选项，或者如果需要选择，可以同时安装两者。这些将突出显示 Django shell 输出的语法，并添加一些其他辅助功能。通过使用以下命令为虚拟环境安装它们：

```py
(env)$ pip install ipython
(env)$ pip install bpython
```

# 如何做...

通过按照以下说明学习使用 Django shell 的基础知识：

+   通过输入以下命令来运行 Django shell：

```py
(env)$ python manage.py shell
```

如果您已安装了`IPython`或`bpython`，那么您安装的任何一个都将在您进入 shell 时自动成为默认接口。您还可以通过在前面的命令中添加`-i <interface>`选项来使用特定的接口。提示符将根据您使用的接口而更改。以下屏幕截图显示了`IPython` shell 可能的外观，以`In [1]:`作为提示开始：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/cee38439-ef1b-4683-9bd3-9a4bd12b37c4.png)

如果您使用`bpython`，则 shell 将显示为带有`>>>`提示，以及在输入时进行代码高亮和文本自动完成，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/1943fe09-c0c4-4e1e-902d-52888447be3c.png)

**默认的 Python 接口** shell 如下所示，也使用`>>>`提示，但前言提供有关系统的信息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/d462bac1-2f1a-47f3-95e5-723b4ccad356.png)

现在您可以导入类、函数或变量，并对它们进行操作。例如，要查看已安装模块的版本，您可以导入该模块，然后尝试读取其`__version__`、`VERSION`或`version`属性（使用`bpython`显示，它还将演示其高亮和自动完成功能），如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/e1ec6437-bcc0-432d-8f95-ea0a9089f663.png)

+   要获取模块、类、函数、方法、关键字或文档主题的全面描述，请使用`help()`函数。您可以传递一个包含特定实体路径的字符串，或者实体本身，如下所示：

```py
>>> help("django.forms")
```

这将打开`django.forms`模块的帮助页面。使用箭头键上下滚动页面。按`Q`键返回到 shell。如果您运行`help()`而没有参数，它会打开一个交互式帮助页面。在那里，您可以输入模块、类、函数等的任何路径，并获取有关其功能和用法的信息。要退出交互式帮助，请按`Ctrl + D`。

+   以下是如何将实体传递给`help()`函数的示例：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/24b5ec75-ff8f-4aa0-8dac-9cca0983c654.png)

这将打开一个`ModelForm`类的帮助页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/9e660105-7b0f-4ee7-a7dd-275a31e0ee46.png)

要快速查看模型实例可用的字段和值，可以使用`__dict__`属性。您可以使用`pprint()`函数以更可读的格式打印字典（不仅仅是一行长），如下面的屏幕截图所示。请注意，当我们使用`__dict__`时，我们不会得到多对多关系；但是，这可能足够快速概述字段和值：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/1944ed9a-8ccd-4814-868d-1cbce7593817.png)

+   要获取对象的所有可用属性和方法，可以使用`dir()`函数，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/5b025518-cda4-4e34-8ec6-8f5d856a6674.png)

+   要每行打印一个属性，可以使用以下屏幕截图中显示的代码：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/f6dd409a-6e5c-48d6-9e54-9986f6050a6f.png)

+   Django shell 对于在将其放入模型方法、视图或管理命令之前尝试`QuerySets`或正则表达式非常有用。例如，要检查电子邮件验证正则表达式，可以在 Django shell 中输入以下内容：

```py
>>> import re
>>> email_pattern = re.compile(r"[^@]+@[^@]+\.[^@]+")
>>> email_pattern.match("aidas@bendoraitis.lt")
<_sre.SRE_Match object at 0x1075681d0>
```

+   如果您想尝试不同的`QuerySets`，请使用以下代码：

```py
>>> from django.contrib.auth.models import User 
>>> User.objects.filter(groups__name="Editors")
[<User: admin>]
```

+   要退出 Django shell，请按*Ctrl* + *D*，或输入以下命令：

```py
>>> exit()
```

# 工作原理...

普通 Python shell 和 Django shell 之间的区别在于，当您运行 Django shell 时，`manage.py`会设置`DJANGO_SETTINGS_MODULE`环境变量，以便它指向项目的`settings.py`路径，然后 Django shell 中的所有代码都在项目的上下文中处理。通过使用第三方 IPython 或 bpython 接口，我们可以进一步增强默认的 Python shell，包括语法高亮、自动完成等。

# 另请参阅

*使用数据库查询表达式*配方

*为更好的国际化支持修补 slugify()函数*配方

# 使用数据库查询表达式

**Django 对象关系映射（ORM）**具有特殊的抽象构造，可用于构建复杂的数据库查询。它们称为**查询表达式**，它们允许您过滤数据、对其进行排序、注释新列并聚合关系。在这个配方中，您将看到这些如何在实践中使用。我们将创建一个应用程序，显示病毒视频，并计算每个视频被匿名用户或登录用户观看的次数。

# 准备工作

首先，创建一个`viral_videos`应用程序，其中包含一个`ViralVideo`模型，并设置系统默认记录到日志文件：

创建`viral_videos`应用程序并将其添加到设置中的`INSTALLED_APPS`下：

```py
# myproject/settings/_base.py
INSTALLED_APPS = [
    # …
    "myproject.apps.core",
    "myproject.apps.viral_videos",
]
```

接下来，创建一个病毒视频的模型，其中包含**通用唯一标识符**（**UUID**）作为主键，以及创建和修改时间戳、标题、嵌入代码、匿名用户的印象和经过身份验证用户的印象，如下所示：

```py
# myproject/apps/viral_videos/models.py import uuid
from django.db import models
from django.utils.translation import ugettext_lazy as _

from myproject.apps.core.models import (
 CreationModificationDateBase,
 UrlBase,
)

class ViralVideo(CreationModificationDateBase, UrlBase):
    uuid = models.UUIDField(primary_key=True, default=None, 
     editable=False)
    title = models.CharField(_("Title"), max_length=200, blank=True)
    embed_code = models.TextField(_("YouTube embed code"), blank=True)
    anonymous_views = models.PositiveIntegerField(_("Anonymous 
     impressions"), default=0)
    authenticated_views = models.PositiveIntegerField(
        _("Authenticated impressions"), default=0
    )

    class Meta:
        verbose_name = _("Viral video")
        verbose_name_plural = _("Viral videos")

    def __str__(self):
        return self.title

    def get_url_path(self):
        from django.urls import reverse

        return reverse("viral_videos:viral_video_detail", 
         kwargs={"pk": self.pk})

    def save(self, *args, **kwargs):
        if self.pk is None:
            self.pk = uuid.uuid4()
        super().save(*args, **kwargs)
```

为新应用程序创建并运行迁移，以便您的数据库准备就绪：

```py
(env)$ python manage.py makemigrations
(env)$ python manage.py migrate
```

将日志配置添加到设置中：

```py
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "file": {
            "level": "DEBUG",
            "class": "logging.FileHandler",
            "filename": os.path.join(BASE_DIR, "tmp", "debug.log"),
        }
    },
    "loggers": {"django": {"handlers": ["file"], "level": "DEBUG", 
     "propagate": True}},
}
```

这将调试信息记录到名为`tmp/debug.log`的临时文件中。

# 如何做...

为了说明查询表达式，让我们创建病毒视频详细视图，并将其插入到 URL 配置中，如下所示：

1.  在`views.py`中创建病毒视频列表和详细视图如下：

```py
# myproject/apps/viral_videos/views.py
import logging

from django.conf import settings
from django.db import models
from django.utils.timezone import now, timedelta
from django.shortcuts import render, get_object_or_404
from django.views.generic import ListView

from .models import ViralVideo

POPULAR_FROM = getattr(settings, "VIRAL_VIDEOS_POPULAR_FROM", 500)

logger = logging.getLogger(__name__)

class ViralVideoList(ListView):
    template_name = "viral_videos/viral_video_list.html"
    model = ViralVideo

def viral_video_detail(request, pk):
    yesterday = now() - timedelta(days=1)

    qs = ViralVideo.objects.annotate(
        total_views=models.F("authenticated_views") + 
         models.F("anonymous_views"),
        label=models.Case(
            models.When(total_views__gt=POPULAR_FROM, 
             then=models.Value("popular")),
            models.When(created__gt=yesterday, 
             then=models.Value("new")),
            default=models.Value("cool"),
            output_field=models.CharField(),
        ),
    )

    # DEBUG: check the SQL query that Django ORM generates
    logger.debug(f"Query: {qs.query}")

    qs = qs.filter(pk=pk)
    if request.user.is_authenticated:
        qs.update(authenticated_views=models
         .F("authenticated_views") + 1)
    else:
        qs.update(anonymous_views=models.F("anonymous_views") + 1)

    video = get_object_or_404(qs)

    return render(request, "viral_videos/viral_video_detail.html", 
     {"video": video})
```

1.  为应用程序定义 URL 配置如下：

```py
# myproject/apps/viral_videos/urls.py
from django.urls import path

from .views import ViralVideoList, viral_video_detail

app_name = "viral_videos"

urlpatterns = [
    path("", ViralVideoList.as_view(), name="viral_video_list"),
    path("<uuid:pk>/", viral_video_detail, 
     name="viral_video_detail"),
]
```

1.  将应用程序的 URL 配置包含在项目的根 URL 配置中，如下所示：

```py
# myproject/urls.py
from django.conf.urls.i18n import i18n_patterns
from django.urls import include, path

urlpatterns = i18n_patterns(
path("viral-videos/", include("myproject.apps.viral_videos.urls", namespace="viral_videos")),
)
```

1.  创建以下病毒视频列表视图的模板：

```py
{# viral_videos/viral_video_list.html #}
{% extends "base.html" %}
{% load i18n %}

{% block content %}
    <h1>{% trans "Viral Videos" %}</h1>
    <ul>
        {% for video in object_list %}
            <li><a href="{{ video.get_url_path }}">
             {{ video.title }}</a></li>
        {% endfor %}
    </ul>
{% endblock %}
```

1.  创建以下病毒视频详细视图的模板：

```py
{# viral_videos/viral_video_detail.html #}
{% extends "base.html" %}
{% load i18n %}

{% block content %}
    <h1>{{ video.title }}
        <span class="badge">{{ video.label }}</span>
    </h1>
    <div>{{ video.embed_code|safe }}</div>
    <div>
        <h2>{% trans "Impressions" %}</h2>
        <ul>
            <li>{% trans "Authenticated views" %}:
                {{ video.authenticated_views }}
            </li>
            <li>{% trans "Anonymous views" %}:
                {{ video.anonymous_views }}
            </li>
            <li>{% trans "Total views" %}:
                {{ video.total_views }}
            </li>
        </ul>
    </div>
{% endblock %}
```

1.  设置`viral_videos`应用程序的管理如下，并在完成后向数据库添加一些视频：

```py
# myproject/apps/viral_videos/admin.py
from django.contrib import admin
from .models import ViralVideo

@admin.register(ViralVideo)
class ViralVideoAdmin(admin.ModelAdmin):
    list_display = ["title", "created", "modified"]
```

# 它是如何工作的...

您可能已经注意到视图中的`logger.debug()`语句。如果以`DEBUG`模式运行服务器并在浏览器中访问视频（例如，在本地开发中访问`http://127.0.0.1:8000/en/viral-videos/2b14ffd3-d1f1-4699-a07b-1328421d8312/`），则会在日志中打印类似以下的 SQL 查询（`tmp/debug.log`）：

```py
SELECT "viral_videos_viralvideo"."created", "viral_videos_viralvideo"."modified", "viral_videos_viralvideo"."uuid", "viral_videos_viralvideo"."title", "viral_videos_viralvideo"."embed_code", "viral_videos_viralvideo"."anonymous_views", "viral_videos_viralvideo"."authenticated_views", ("viral_videos_viralvideo"."authenticated_views" + "viral_videos_viralvideo"."anonymous_views") AS "total_views", CASE WHEN ("viral_videos_viralvideo"."authenticated_views" + "viral_videos_viralvideo"."anonymous_views") > 500 THEN 'popular' WHEN "viral_videos_viralvideo"."created" > '2019-12-21T05:01:58.775441+00:00'::timestamptz THEN 'new' ELSE 'cool' END 
 AS "label" FROM "viral_videos_viralvideo" WHERE "viral_videos_viralvideo"."uuid" = '2b14ffd3-d1f1-4699-a07b-1328421d8312'::uuid LIMIT 21; args=(500, 'popular', datetime.datetime(2019, 12, 21, 5, 1, 58, 775441, tzinfo=<UTC>), 'new', 'cool', UUID('2b14ffd3-d1f1-4699-a07b-1328421d8312'))
```

然后，在浏览器中，您将看到一个简单的页面，显示如下内容：

+   视频的标题

+   视频的标签

+   嵌入式视频

+   经过身份验证和匿名用户的观看次数，以及总观看次数

它将类似于以下图像：

！[](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/4a1f0dea-f959-4597-879d-5e24a3470968.png)

Django `QuerySets`中的`annotate()`方法允许您向`SELECT` SQL 语句添加额外的列，以及为从`QuerySets`检索的对象创建的临时属性。使用`models.F()`，我们可以引用所选数据库表中的不同字段值。在此示例中，我们将创建`total_views`属性，该属性是经过身份验证和匿名用户查看的总和。

使用`models.Case()`和`models.When()`，我们可以根据不同的条件返回值。为了标记这些值，我们使用`models.Value()`。在我们的示例中，我们将为 SQL 查询创建`label`列，并为`QuerySet`返回的对象创建属性。如果有超过 500 次印象，则将其设置为 popular，如果在过去的 24 小时内创建，则设置为 new，否则设置为 cool。

在视图的末尾，我们调用了`qs.update()`方法。它们会增加当前视频的`authenticated_views`或`anonymous_views`，具体取决于查看视频的用户是否已登录。增加不是在 Python 级别进行的，而是在 SQL 级别进行的。这解决了所谓的竞争条件问题，即两个或更多访问者同时访问视图，尝试同时增加视图计数的问题。

# 另请参阅

+   *在 Django shell 中使用*的方法

+   第二章*，模型和数据库结构*中的*使用 URL 相关方法创建模型 mixin*的方法

+   第二章*，模型和数据库结构*中的*创建处理创建和修改日期的模型 mixin*的方法

# 为了更好地支持国际化，对 slugify()函数进行猴子补丁

猴子补丁（或游击补丁）是一段代码，它在运行时扩展或修改另一段代码。不建议经常使用猴子补丁；但是，有时它们是修复复杂的第三方模块中的错误的唯一可能方法，而不是创建模块的单独分支。此外，猴子补丁可以用于准备功能或单元测试，而无需使用复杂和耗时的数据库或文件操作。

在这个示例中，您将学习如何使用第三方`transliterate`包中的函数来替换默认的`slugify()`函数，该函数更智能地处理 Unicode 字符到 ASCII 等效字符的转换，并包含许多语言包，根据需要提供更具体的转换。快速提醒，我们使用`slugify()`实用程序来创建对象标题或上传文件名的 URL 友好版本。处理时，该函数会删除任何前导和尾随空格，将文本转换为小写，删除非字母数字字符，并将空格转换为连字符。

# 准备就绪

让我们从这些小步骤开始：

1.  按照以下方式在虚拟环境中安装`transliterate`：

```py
(env)$ pip install transliterate==1.10.2
```

1.  然后，在项目中创建一个`guerrilla_patches`应用，并将其放在设置中的`INSTALLED_APPS`下。

# 如何做...

在`guerrilla_patches`应用的`models.py`文件中，用`transliterate`包中的`slugify`函数覆盖`django.utils.text`中的`slugify`函数：

```py
# myproject/apps/guerrilla_patches/models.py from django.utils import text
from transliterate import slugify

text.slugify = slugify
```

# 它是如何工作的...

默认的 Django `slugify()`函数不正确地处理德语变音符号。要自己看看，请尝试使用所有德语变音符号的非常长的德语单词进行 slugify。首先，在 Django shell 中运行以下代码，不使用 monkey patch：

```py
(env)$ python manage.py shell
>>> from django.utils.text import slugify
>>> slugify("Heizölrückstoßabdämpfung")
'heizolruckstoabdampfung'
```

这在德语中是不正确的，因为字母`ß`被完全剥离，而不是被替换为`ss`，字母`ä`，`ö`和`ü`被改为`a`，`o`和`u`，而它们应该被替换为`ae`，`oe`和`ue`。

我们创建的 monkey patch 在初始化时加载了`django.utils.text`模块，并在核心`slugify()`函数的位置重新分配了`transliteration.slugify`。现在，如果您在 Django shell 中运行相同的代码，您将得到正确的结果，如下所示：

```py
(env)$ python manage.py shell
>>> from django.utils.text import slugify
>>> slugify("Heizölrückstoßabdämpfung")
'heizoelrueckstossabdaempfung'
```

要了解如何使用`transliterate`模块，请参阅[`pypi.org/project/transliterate`](https://pypi.org/project/transliterate/)。

# 还有更多...

在创建 monkey patch 之前，我们需要完全了解要修改的代码的工作原理。这可以通过分析现有代码并检查不同变量的值来完成。为此，有一个有用的内置 Python 调试器模块**pdb**，可以临时添加到 Django 代码（或任何第三方模块）中，在任何断点处停止开发服务器的执行。使用以下代码调试 Python 模块中不清楚的部分：

```py
breakpoint()
```

这将启动交互式 shell，您可以在其中输入变量以查看它们的值。如果输入`c`或`continue`，代码执行将继续直到下一个断点。如果输入`q`或`quit`，管理命令将被中止。

您可以在[`docs.python.org/3/library/pdb.html`](https://docs.python.org/3/library/pdb.html)了解更多 Python 调试器命令以及如何检查代码的回溯。

在开发服务器中查看变量值的另一种快速方法是通过引发带有变量作为消息的警告，如下所示：

```py
raise Warning, some_variable

```

当您处于`DEBUG`模式时，Django 记录器将为您提供回溯和其他本地变量。

在将工作提交到存储库之前，请不要忘记删除调试代码。

如果您使用 PyCharm 交互式开发环境，可以在那里设置断点并直观地调试变量，而无需修改源代码。

# 另请参阅

+   *使用 Django shell*示例

# 切换调试工具栏

在使用 Django 进行开发时，您可能希望检查请求标头和参数，检查当前模板上下文，或者测量 SQL 查询的性能。所有这些以及更多功能都可以通过**Django Debug Toolbar**实现。它是一组可配置的面板，显示有关当前请求和响应的各种调试信息。在本教程中，我们将指导您如何根据一个由书签工具设置的 cookie 的值来切换调试工具栏的可见性。书签工具是一个带有一小段 JavaScript 代码的书签，您可以在浏览器中的任何页面上运行它。

# 准备工作

要开始切换调试工具栏的可见性，请按照以下步骤进行：

1.  在虚拟环境中安装 Django Debug Toolbar：

```py
(env)$ pip install django-debug-toolbar==2.1

```

1.  在设置的`INSTALLED_APPS`下添加`"debug_toolbar"`：

```py
# myproject/settings/_base.py
INSTALLED_APPS = [
    # …
    "debug_toolbar",
]
```

# 如何做...

按照以下步骤设置 Django Debug Toolbar，可以使用浏览器中的书签工具切换开启或关闭：

1.  添加以下项目设置：

```py
# myproject/settings/_base.py
DEBUG_TOOLBAR_CONFIG = {
    "DISABLE_PANELS": [],
    "SHOW_TOOLBAR_CALLBACK": 
    "myproject.apps.core.misc.custom_show_toolbar",
    "SHOW_TEMPLATE_CONTEXT": True,
}

DEBUG_TOOLBAR_PANELS = [
    "debug_toolbar.panels.versions.VersionsPanel",
    "debug_toolbar.panels.timer.TimerPanel",
    "debug_toolbar.panels.settings.SettingsPanel",
    "debug_toolbar.panels.headers.HeadersPanel",
    "debug_toolbar.panels.request.RequestPanel",
    "debug_toolbar.panels.sql.SQLPanel",
    "debug_toolbar.panels.templates.TemplatesPanel",
    "debug_toolbar.panels.staticfiles.StaticFilesPanel",
    "debug_toolbar.panels.cache.CachePanel",
    "debug_toolbar.panels.signals.SignalsPanel",
    "debug_toolbar.panels.logging.LoggingPanel",
    "debug_toolbar.panels.redirects.RedirectsPanel",
]
```

1.  在`core`应用程序中，创建一个带有`custom_show_toolbar()`函数的`misc.py`文件，如下所示：

```py
# myproject/apps/core/misc.py
def custom_show_toolbar(request):
    return "1" == request.COOKIES.get("DebugToolbar", False)
```

1.  在项目的`urls.py`中，添加以下配置规则：

```py
# myproject/urls.py
from django.conf.urls.i18n import i18n_patterns
from django.urls import include, path
from django.conf import settings
import debug_toolbar

urlpatterns = i18n_patterns(
    # …
)

urlpatterns = [
    path('__debug__/', include(debug_toolbar.urls)),
] + urlpatterns
```

1.  打开 Chrome 或 Firefox 浏览器，转到书签管理器。然后，创建两个包含 JavaScript 的新书签。第一个链接将显示工具栏，看起来类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/eb9e72cf-62f5-499f-80d5-af10e85065c7.png)

JavaScript 代码如下：

```py
javascript:(function(){document.cookie="DebugToolbar=1; path=/";location.reload();})();
```

1.  第二个 JavaScript 链接将隐藏工具栏，看起来类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/1894ef15-be7e-4e6a-b76a-5b69c7d710c1.png)

这是完整的 JavaScript 代码：

```py
javascript:(function(){document.cookie="DebugToolbar=0; path=/";location.reload();})();
```

# 工作原理...

`DEBUG_TOOLBAR_PANELS`设置定义了工具栏中要显示的面板。`DEBUG_TOOLBAR_CONFIG`字典定义了工具栏的配置，包括用于检查是否显示工具栏的函数的路径。

默认情况下，当您浏览项目时，Django Debug Toolbar 不会显示；但是，当您单击书签工具 Debug Toolbar On 时，`DebugToolbar` cookie 将被设置为`1`，页面将被刷新，您将看到带有调试面板的工具栏，例如，您将能够检查 SQL 语句的性能以进行优化，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/522d836e-d3fa-4c80-8f8f-64fb91b4789e.png)

您还可以检查当前视图的模板上下文变量，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/fc773aa8-5179-435c-a50d-d4efc15bf495.png)

单击第二个书签工具 Debug Toolbar Off，将类似地将`DebugToolbar` cookie 设置为`0`并刷新页面，再次隐藏工具栏。

# 另请参阅

+   *通过电子邮件获取详细的错误报告*教程在第十三章*维护*中

# 使用 ThreadLocalMiddleware

`HttpRequest`对象包含有关当前用户、语言、服务器变量、cookie、会话等的有用信息。事实上，`HttpRequest`在视图和中间件中提供，并且您可以将其（或其属性值）传递给表单、模型方法、模型管理器、模板等。为了简化生活，您可以使用所谓的`ThreadLocalMiddleware`，它将当前的`HttpRequest`对象存储在全局可访问的 Python 线程中。因此，您可以从模型方法、表单、信号处理程序和以前无法直接访问`HttpRequest`对象的其他位置访问它。在本教程中，我们将定义这个中间件。

# 准备工作

如果尚未这样做，请创建`core`应用程序并将其放在设置的`INSTALLED_APPS`下。

# 如何做...

执行以下两个步骤来设置`ThreadLocalMiddleware`，它可以在项目代码的任何函数或方法中获取当前的`HttpRequest`或用户：

1.  在`core`应用程序中添加一个`middleware.py`文件，内容如下：

```py
# myproject/apps/core/middleware.py
from threading import local

_thread_locals = local()

def get_current_request():
    """
    :returns the HttpRequest object for this thread
    """
    return getattr(_thread_locals, "request", None)

def get_current_user():
    """
    :returns the current user if it exists or None otherwise """
    request = get_current_request()
    if request:
        return getattr(request, "user", None)

class ThreadLocalMiddleware(object):
    """
    Middleware to add the HttpRequest to thread local storage
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _thread_locals.request = request
        return self.get_response(request)
```

1.  将此中间件添加到设置中的`MIDDLEWARE`中：

```py
# myproject/settings/_base.py
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "debug_toolbar.middleware.DebugToolbarMiddleware",
 "myproject.apps.core.middleware.ThreadLocalMiddleware",
]
```

# 它是如何工作的...

`ThreadLocalMiddleware` 处理每个请求，并将当前的 `HttpRequest` 对象存储在当前线程中。Django 中的每个请求-响应周期都是单线程的。我们创建了两个函数：`get_current_request()` 和 `get_current_user()`。这些函数可以从任何地方使用，以分别获取当前的 `HttpRequest` 对象或当前用户。

例如，您可以使用此中间件来开发和使用 `CreatorMixin`，它将保存当前用户作为新模型对象的创建者，如下所示：

```py
# myproject/apps/core/models.py
from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

class CreatorBase(models.Model):
    """
    Abstract base class with a creator
    """

    creator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_("creator"),
        editable=False,
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
    )

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        from .middleware import get_current_user

        if not self.creator:
 self.creator = get_current_user()
        super().save(*args, **kwargs)

    save.alters_data = True
```

# 另请参阅

+   第二章*，模型和数据库结构*中的*创建一个具有与 URL 相关方法的模型混合*教程

+   第二章*，模型和数据库结构*中的*创建一个处理创建和修改日期的模型混合*教程

+   第二章*，模型和数据库结构*中的*创建一个处理元标签的模型混合*教程

+   第二章*，模型和数据库结构*中的*创建一个处理通用关系的模型混合*教程

# 使用信号通知管理员有关新条目

Django 框架包括**信号**的概念，类似于 JavaScript 中的事件。有一些内置的信号。您可以使用它们在模型初始化之前和之后触发操作，保存或删除实例，迁移数据库模式，处理请求等。此外，您可以在可重用的应用程序中创建自己的信号，并在其他应用程序中处理它们。在本教程中，您将学习如何使用信号在特定模型保存时向管理员发送电子邮件。

# 准备工作

让我们从我们在*使用数据库查询表达式*教程中创建的 `viral_videos` 应用程序开始。

# 如何做...

按照以下步骤为管理员创建通知：

1.  创建一个名为 `signals.py` 的文件，内容如下：

```py
# myproject/apps/viral_videos/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.template.loader import render_to_string

from .models import ViralVideo

@receiver(post_save, sender=ViralVideo)
def inform_administrators(sender, **kwargs):
    from django.core.mail import mail_admins

    instance = kwargs["instance"]
    created = kwargs["created"]

    if created:
        context = {"title": instance.title, "link": 
         instance.get_url()}
        subject = render_to_string(
            "viral_videos/email/administrator/subject.txt", context
        )
        plain_text_message = render_to_string(
            "viral_videos/email/administrator/message.txt", context
        )
        html_message = render_to_string(
            "viral_videos/email/administrator/message.html", 
              context
        )

        mail_admins(
            subject=subject.strip(),
            message=plain_text_message,
            html_message=html_message,
            fail_silently=True,
        )
```

1.  然后我们需要创建一些模板。首先是电子邮件主题的模板：

```py
{# viral_videos/email/administrator/subject.txt #}
New Viral Video Added
```

1.  然后创建一个纯文本消息的模板，类似于以下内容：

```py
{# viral_videos/email/administrator/message.txt #}
A new viral video called "{{ title }}" has been created.
You can preview it at {{ link }}.
```

1.  然后创建一个 HTML 消息的模板如下：

```py
{# viral_videos/email/administrator/message.html #}
<p>A new viral video called "{{ title }}" has been created.</p>
<p>You can <a href="{{ link }}">preview it here</a>.</p>
```

1.  创建一个名为 `apps.py` 的文件，内容如下：

```py
# myproject/apps/viral_videos/apps.py
from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _

class ViralVideosAppConfig(AppConfig):
    name = "myproject.apps.viral_videos"
    verbose_name = _("Viral Videos")

    def ready(self):
        from .signals import inform_administrators
```

1.  使用以下内容更新 `__init__.py` 文件：

```py
# myproject/apps/viral_videos/__init__.py
default_app_config = "myproject.apps.viral_videos.apps.ViralVideosAppConfig"
```

确保在项目设置中设置了类似以下内容的 `ADMINS`：

```py
# myproject/settings/_base.py
ADMINS = [("Administrator", "admin@example.com")]
```

# 它是如何工作的...

`ViralVideosAppConfig` 应用配置类具有 `ready()` 方法，当项目的所有模型加载到内存中时将调用该方法。根据 Django 文档，信号允许特定发送者通知一组接收者发生了某个动作。因此，在 `ready()` 方法中，我们导入 `inform_administrators()` 函数。

通过 `@receiver` 装饰器，`inform_administrators()` 被注册为 `post_save` 信号的接收者，并且我们将其限制为仅处理 `ViralVideo` 模型为 `sender` 的信号。因此，每当我们保存 `ViralVideo` 对象时，将调用 `receiver` 函数。`inform_administrators()` 函数检查视频是否是新创建的。如果是，它会向在设置中列出的系统管理员发送电子邮件。

我们使用模板生成 `subject`、`plain_text_message` 和 `html_message` 的内容，以便我们可以在我们的应用程序中为每个定义默认模板。如果我们将我们的 `viral_videos` 应用程序公开可用，那些将其引入其自己项目的人可以根据需要自定义模板，也许将它们包装在公司电子邮件模板包装器中。

您可以在官方文档 [`docs.djangoproject.com/en/3.0/topics/signals/`](https://docs.djangoproject.com/en/3.0/topics/signals/) 中了解有关 Django 信号的更多信息。

# 另请参阅

+   在第一章*, Getting Started with Django 3.0*中的*创建应用程序配置*配方

+   使用数据库查询表达式的配方

+   检查缺失设置的配方

# 检查缺失设置

从 Django 1.7 开始，您可以使用一个可扩展的**系统检查框架**，它取代了旧的`validate`管理命令。在这个配方中，您将学习如何创建一个检查，以查看`ADMINS`设置是否已设置。同样，您还可以检查您正在使用的 API 是否设置了不同的密钥或访问令牌。

# 准备工作

让我们从在*使用数据库查询表达式*配方中创建并在上一个配方中扩展的`viral_videos`应用程序开始。

# 如何做...

要使用系统检查框架，请按照以下步骤进行：

1.  创建`checks.py`文件，内容如下：

```py
# myproject/apps/viral_videos/checks.py
from textwrap import dedent

from django.core.checks import Warning, register, Tags

@register(Tags.compatibility)
def settings_check(app_configs, **kwargs):
    from django.conf import settings

    errors = []

    if not settings.ADMINS:
        errors.append(
            Warning(
                dedent("""
                    The system admins are not set in the project 
                     settings
                """),
                obj=settings,
                hint=dedent("""
                    In order to receive notifications when new 
                     videos are created, define system admins 
                     in your settings, like:

                    ADMINS = (
                        ("Admin", "administrator@example.com"),
                    )
                """),
                id="viral_videos.W001",
            )
        )

    return errors
```

1.  在应用程序配置的`ready()`方法中导入检查，如下所示：

```py
# myproject/apps/viral_videos/apps.py
from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _

class ViralVideosAppConfig(AppConfig):
    name = "myproject.apps.viral_videos"
    verbose_name = _("Viral Videos")

    def ready(self):
        from .signals import inform_administrators
        from .checks import settings_check
```

1.  要尝试刚刚创建的检查，删除或注释掉`ADMINS`设置，然后在虚拟环境中运行`check`管理命令：

```py
(env)$ python manage.py check
System check identified some issues:

WARNINGS:
<Settings "myproject.settings.dev">: (viral_videos.W001)
The system admins are not set in the project settings

HINT:
In order to receive notifications when new videos are
created, define system admins in your settings, like:

ADMINS = (
    ("Admin", "administrator@example.com"),
)

System check identified 1 issue (0 silenced).
```

# 它是如何工作的...

系统检查框架在模型、字段、数据库、管理身份验证配置、内容类型和安全设置中有一堆检查，如果项目中的某些内容设置不正确，它会引发错误或警告。此外，您可以创建自己的检查，类似于我们在这个配方中所做的。

我们已经注册了`settings_check()`函数，如果项目中没有定义`ADMINS`设置，则返回一个带有`Warning`的列表。

除了来自`django.core.checks`模块的`Warning`实例外，返回的列表还可以包含`Debug`、`Info`、`Error`和`Critical`内置类的实例，或者继承自`django.core.checks.CheckMessage`的任何其他类。在调试、信息和警告级别记录会静默失败，而在错误和严重级别记录会阻止项目运行。

在这个例子中，通过将`Tags.compatibility`参数传递给`@register`装饰器，将检查标记为兼容性检查。`Tags`中提供的其他选项包括以下内容：

+   `admin`用于与管理员站点相关的检查

+   `caches`用于与服务器缓存相关的检查

+   `database`用于与数据库配置相关的检查

+   `models`用于与模型、模型字段和管理器相关的检查

+   `security`用于与安全相关的检查

+   `信号`用于与信号声明和处理程序相关的检查

+   `staticfiles`用于静态文件检查

+   `templates`用于与模板相关的检查

+   `translation`用于与字符串翻译相关的检查

+   `url`用于与 URL 配置相关的检查

在官方文档中了解有关系统检查框架的更多信息[`docs.djangoproject.com/en/3.0/topics/checks/`](https://docs.djangoproject.com/en/3.0/topics/checks/)​。

# 另请参阅

+   在第一章*, Getting Started with Django 3.0*中的*创建应用程序配置*配方

+   使用数据库查询表达式的配方

+   使用信号通知管理员有关新条目的配方
