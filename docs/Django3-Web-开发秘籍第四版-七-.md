# Django3 Web 开发秘籍第四版（七）

> 原文：[`zh.annas-archive.org/md5/49CC5D4E5506D0966D8746F9F4B56200`](https://zh.annas-archive.org/md5/49CC5D4E5506D0966D8746F9F4B56200)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：测试

在本章中，我们将涵盖以下主题：

+   使用 mock 测试视图

+   使用 Selenium 测试用户界面

+   使用 Django REST 框架创建 API 的测试

+   确保测试覆盖率

# 介绍

为了确保代码的质量和正确性，您应该进行自动化软件测试。 Django 为您提供了编写网站测试套件的工具。 测试套件会自动检查您的网站及其组件，以确保一切正常运行。 当您修改代码时，可以运行测试以检查您的更改是否对应用程序的行为产生了负面影响。

自动化软件测试领域有各种划分和术语。 为了本书的目的，我们将测试划分为以下类别：

+   **单元测试**指的是严格针对代码的单个部分或单元的测试。 最常见的情况是，一个单元对应于单个文件或模块，单元测试会尽力验证逻辑和行为是否符合预期。

+   **集成测试**进一步进行，处理两个或多个单元彼此协作的方式。 这种测试不像单元测试那样细粒度，并且通常是在假设所有单元测试都已通过的情况下编写的。 因此，集成测试仅涵盖了必须对单元正确地彼此协作的行为集。

+   **组件接口测试**是集成测试的一种高阶形式，其中单个组件从头到尾进行验证。 这种测试以一种对提供组件行为的基础逻辑无知的方式编写，因此逻辑可以更改而不修改行为，测试仍将通过。

+   系统测试验证了构成系统的所有组件的端到端集成，通常对应于完整的用户流程。

+   **操作接受测试**检查系统的所有非功能方面是否正常运行。 验收测试检查业务逻辑，以找出项目是否按照最终用户的观点正常工作。

# 技术要求

要使用本章中的代码，您需要最新稳定版本的 Python，一个 MySQL 或 PostgreSQL 数据库，以及一个带有虚拟环境的 Django 项目。

您可以在 GitHub 存储库的`ch11`目录中找到本章的所有代码：[`github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition`](https://github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition)。

# 使用 mock 测试视图

在本示例中，我们将看看如何编写单元测试。 单元测试检查单个函数或方法是否返回正确的结果。 我们将查看`likes`应用程序，并编写测试，检查对`json_set_like()`视图的发布是否对未经身份验证的用户返回失败响应，并对经过身份验证的用户返回成功结果。 我们将使用`Mock`对象来模拟`HttpRequest`和`AnonymousUser`对象。

# 准备工作

让我们从*在第四章*的*实现点赞小部件*食谱中的`locations`和`likes`应用程序开始。

我们将使用`mock`库，自 Python 3.3 以来一直作为内置的`unittest.mock`可用。

# 如何操作...

我们将通过以下步骤使用`mock`测试点赞操作：

1.  在`likes`应用中创建`tests`模块

1.  在本模块中，创建一个名为`test_views.py`的文件，内容如下：

```py
# myproject/apps/likes/tests/test_views.py
import json
from unittest import mock
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from myproject.apps.locations.models import Location

class JSSetLikeViewTest(TestCase):
    @classmethod
    def setUpClass(cls):
        super(JSSetLikeViewTest, cls).setUpClass()

        cls.location = Location.objects.create(
            name="Park Güell",
            description="If you want to see something spectacular, 
            come to Barcelona, Catalonia, Spain and visit Park 
            Güell. Located on a hill, Park Güell is a public 
            park with beautiful gardens and organic 
            architectural elements.",
            picture="locations/2020/01/20200101012345.jpg",  
            # dummy path
        )
        cls.content_type = 
         ContentType.objects.get_for_model(Location)
        cls.superuser = User.objects.create_superuser(
            username="admin", password="admin", 
             email="admin@example.com"
        )

    @classmethod
    def tearDownClass(cls):
        super(JSSetLikeViewTest, cls).tearDownClass()
        cls.location.delete()
        cls.superuser.delete()

    def test_authenticated_json_set_like(self):
        from ..views import json_set_like

        mock_request = mock.Mock()
        mock_request.user = self.superuser
        mock_request.method = "POST"

        response = json_set_like(mock_request, 
         self.content_type.pk, self.location.pk)
        expected_result = json.dumps(
            {"success": True, "action": "add", "count": 
             Location.objects.count()}
        )
        self.assertJSONEqual(response.content, expected_result)

    @mock.patch("django.contrib.auth.models.User")
    def test_anonymous_json_set_like(self, MockUser):
        from ..views import json_set_like

        anonymous_user = MockUser()
        anonymous_user.is_authenticated = False

        mock_request = mock.Mock()
        mock_request.user = anonymous_user
        mock_request.method = "POST"

        response = json_set_like(mock_request, 
        self.content_type.pk, self.location.pk)
        expected_result = json.dumps({"success": False})
        self.assertJSONEqual(response.content, expected_result)
```

1.  运行`likes`应用的测试，如下所示：

```py
(env)$ python manage.py test myproject.apps.likes --settings=myproject.settings.test
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
..
----------------------------------------------------------------------
Ran 2 tests in 0.268s
OK
Destroying test database for alias 'default'...
```

# 工作原理...

当您运行`likes`应用的测试时，首先会创建一个临时测试数据库。然后，会调用`setUpClass()`方法。稍后，将执行以`test`开头的方法，最后会调用`tearDownClass()`方法。对于每个通过的测试，您将在命令行工具中看到一个点（.），对于每个失败的测试，将会有一个字母 F，对于测试中的每个错误，您将看到字母 E。最后，您将看到有关失败和错误测试的提示。因为我们目前在`likes`应用的套件中只有两个测试，所以您将在结果中看到两个点。

在`setUpClass()`中，我们创建一个位置和一个超级用户。此外，我们找出`Location`模型的`ContentType`对象。我们将需要它用于`json_set_like()`视图，该视图为不同对象设置或移除喜欢。作为提醒，该视图看起来类似于以下内容，并返回一个 JSON 字符串作为结果：

```py
def json_set_like(request, content_type_id, object_id):
    # all the view logic goes here…
    return JsonResponse(result)
```

在`test_authenticated_json_set_like()`和`test_anonymous_json_set_like()`方法中，我们使用`Mock`对象。这些对象可以具有任何属性或方法。`Mock`对象的每个未定义属性或方法都是另一个`Mock`对象。因此，在 shell 中，您可以尝试链接属性，如下所示：

```py
>>> from unittest import mock
>>> m = mock.Mock()
>>> m.whatever.anything().whatsoever
<Mock name='mock.whatever.anything().whatsoever' id='4320988368'>
```

在我们的测试中，我们使用`Mock`对象来模拟`HttpRequest`对象。对于匿名用户，`MockUser`被生成为标准 Django `User`对象的一个补丁，通过`@mock.patch()`装饰器。对于经过身份验证的用户，我们仍然需要真实的`User`对象，因为视图使用用户的 ID 来获取`Like`对象。

因此，我们调用`json_set_like()`函数，并检查返回的 JSON 响应是否正确：

+   如果访问者未经身份验证，则响应中返回`{"success": false}`

+   对于经过身份验证的用户，它返回类似`{"action": "add", "count": 1, "success": true}`的内容

最后，调用`tearDownClass()`类方法，从测试数据库中删除位置和超级用户。

# 还有更多...

要测试使用`HttpRequest`对象的内容，您还可以使用 Django 请求工厂。您可以在[`docs.djangoproject.com/en/3.0/topics/testing/advanced/#the-request-factory`](https://docs.djangoproject.com/en/3.0/topics/testing/advanced/#the-request-factory)上阅读如何使用它。

# 另请参阅

+   在第四章*，模板和 JavaScript*中的*实现“喜欢”小部件*食谱中

+   *使用 Selenium 测试用户界面*食谱

+   *使用 Django REST 框架创建 API 的测试*食谱

+   *确保测试覆盖*食谱

# 使用 Selenium 测试用户界面

**操作接受测试**检查业务逻辑，以了解项目是否按预期工作。在这个食谱中，您将学习如何使用**Selenium**编写接受测试，它允许您模拟前端的活动，如填写表单或在浏览器中单击特定的 DOM 元素。

# 准备工作

让我们从第四章*，模板和 JavaScript*中的*实现“喜欢”小部件*食谱中的`locations`和`likes`应用开始。

对于这个食谱，我们将使用 Selenium 库与**Chrome**浏览器和**ChromeDriver**来控制它。让我们准备一下：

1.  从[`www.google.com/chrome/`](https://www.google.com/chrome/)下载并安装 Chrome 浏览器。

1.  在 Django 项目中创建一个`drivers`目录。从[`sites.google.com/a/chromium.org/chromedriver/`](https://sites.google.com/a/chromium.org/chromedriver/)下载 ChromeDriver 的最新稳定版本，解压缩并将其放入新创建的`drivers`目录中。

1.  在虚拟环境中安装 Selenium，如下所示：

```py
(env)$ pip install selenium
```

# 如何做...

我们将通过 Selenium 测试基于 Ajax 的点赞功能，执行以下步骤：

1.  在项目设置中，添加一个`TESTS_SHOW_BROWSER`设置：

```py
# myproject/settings/_base.py
TESTS_SHOW_BROWSER = True
```

1.  在您的`locations`应用中创建`tests`模块，并在其中添加一个`test_frontend.py`文件，内容如下：

```py
# myproject/apps/locations/tests/test_frontend.py
import os
from io import BytesIO
from time import sleep

from django.core.files.storage import default_storage
from django.test import LiveServerTestCase
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User
from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from myproject.apps.likes.models import Like
from ..models import Location

SHOW_BROWSER = getattr(settings, "TESTS_SHOW_BROWSER", False)

@override_settings(DEBUG=True)
class LiveLocationTest(LiveServerTestCase):
    @classmethod
    def setUpClass(cls):
        super(LiveLocationTest, cls).setUpClass()
        driver_path = os.path.join(settings.BASE_DIR, "drivers", 
        "chromedriver")
        chrome_options = Options()
        if not SHOW_BROWSER:
 chrome_options.add_argument("--headless")
        chrome_options.add_argument("--window-size=1200,800")

        cls.browser = webdriver.Chrome(
            executable_path=driver_path, options=chrome_options
        )
        cls.browser.delete_all_cookies()

        image_path = cls.save_test_image("test.jpg")
        cls.location = Location.objects.create(
            name="Park Güell",
            description="If you want to see something spectacular, 
             come to Barcelona, Catalonia, Spain and visit Park 
             Güell. Located on a hill, Park Güell is a public 
             park with beautiful gardens and organic 
             architectural elements.",
            picture=image_path,  # dummy path
        )
        cls.username = "admin"
        cls.password = "admin"
        cls.superuser = User.objects.create_superuser(
            username=cls.username, password=cls.password, 
             email="admin@example.com"
        )

    @classmethod
    def tearDownClass(cls):
        super(LiveLocationTest, cls).tearDownClass()
        cls.browser.quit()
        cls.location.delete()
        cls.superuser.delete()

    @classmethod
    def save_test_image(cls, filename):
        from PIL import Image

        image = Image.new("RGB", (1, 1), 0)
        image_buffer = BytesIO()
        image.save(image_buffer, format="JPEG")
        path = f"tests/{filename}"
        default_storage.save(path, image_buffer)
        return path

    def wait_a_little(self):
        if SHOW_BROWSER:
 sleep(2)

    def test_login_and_like(self):
        # login
        login_path = reverse("admin:login")
        self.browser.get(
            f"{self.live_server_url}{login_path}?next=
          {self.location.get_url_path()}"
        )
        username_field = 
        self.browser.find_element_by_id("id_username")
        username_field.send_keys(self.username)
        password_field = 
        self.browser.find_element_by_id("id_password")
        password_field.send_keys(self.password)
        self.browser.find_element_by_css_selector
        ('input[type="submit"]').click()
        WebDriverWait(self.browser, timeout=10).until(
            lambda x: 
       self.browser.find_element_by_css_selector(".like-button")
        )
        # click on the "like" button
        like_button = 
       self.browser.find_element_by_css_selector(".like-button")
        is_initially_active = "active" in 
         like_button.get_attribute("class")
        initial_likes = int(
            self.browser.find_element_by_css_selector
             (".like-badge").text
        )

        self.assertFalse(is_initially_active)
        self.assertEqual(initial_likes, 0)

        self.wait_a_little()

        like_button.click()
        WebDriverWait(self.browser, timeout=10).until(
            lambda x:  
            int(self.browser.find_element_by_css_selector
             (".like-badge").text) != initial_likes
        )
        likes_in_html = int(
            self.browser.find_element_by_css_selector
             (".like-badge").text
        )
        likes_in_db = Like.objects.filter(

       content_type=ContentType.objects.get_for_model(Location),
            object_id=self.location.pk,
        ).count()
        self.assertEqual(likes_in_html, 1)
        self.assertEqual(likes_in_html, likes_in_db)

        self.wait_a_little()

        self.assertGreater(likes_in_html, initial_likes)

        # click on the "like" button again to switch back to the 
        # previous state
        like_button.click()
        WebDriverWait(self.browser, timeout=10).until(
            lambda x: int(self.browser.find_element_by_css_selector
            (".like-badge").text) == initial_likes
        )

        self.wait_a_little()
```

1.  运行`locations`应用的测试，如下所示：

```py
(env)$ python manage.py test myproject.apps.locations --settings=myproject.settings.test
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
.
----------------------------------------------------------------------
Ran 1 test in 4.284s

OK
Destroying test database for alias 'default'...
```

# 它是如何工作的...

当我们运行这些测试时，我们将看到一个 Chrome 窗口打开，显示管理登录屏幕的 URL，例如

`http://localhost:63807/en/admin/login/?next=/en/locations/176255a9-9c07-4542-8324-83ac0d21b7c3/`。

用户名和密码字段将填写为 admin，然后您将被重定向到 Park Güell 位置的详细页面，URL 如下

`http://localhost:63807/en/locations/176255a9-9c07-4542-8324-83ac0d21b7c3/`。在那里，您将看到点赞按钮被点击两次，导致点赞和取消点赞操作。

如果我们将`TESTS_SHOW_BROWSER`设置为`False`（或将其全部删除）并再次运行测试，测试将以最小的等待时间在后台进行，而不会打开浏览器窗口。

让我们看看这在测试套件中是如何工作的。我们定义一个扩展`LiveServerTestCase`的类。这将创建一个测试套件，该测试套件将在一个随机未使用的端口（例如`63807`）下运行一个本地服务器。默认情况下，`LiveServerTestCase`以非 DEBUG 模式运行服务器。但是，我们使用`override_settings()`装饰器将其切换到 DEBUG 模式，以便使静态文件可访问而无需收集它们，并在任何页面上发生错误时显示错误回溯。`setUpClass()`类方法将在所有测试开始时执行，`tearDownClass()`类方法将在测试运行后执行。在中间，测试将执行所有以`test`开头的套件方法。

当我们开始测试时，会创建一个新的测试数据库。在`setUpClass()`中，我们创建一个浏览器对象，一个位置和一个超级用户。然后，执行`test_login_and_like()`方法，该方法打开管理登录页面，找到用户名字段，输入管理员的用户名，找到密码字段，输入管理员的密码，找到提交按钮，并点击它。然后，它等待最多 10 秒，直到页面上可以找到具有`.like-button` CSS 类的 DOM 元素。

正如您可能记得的*在第四章*中实现点赞小部件的教程，模板和 JavaScript，我们的小部件由两个元素组成：

+   一个点赞按钮

+   显示点赞总数的徽章

如果点击按钮，您的`Like`实例将通过 Ajax 调用添加或从数据库中删除。此外，徽章计数将更新以反映数据库中的点赞数。

在测试中，我们检查按钮的初始状态（是否具有`.active` CSS 类），检查初始点赞数，并模拟点击按钮。我们等待最多 10 秒，直到徽章中的计数发生变化。然后，我们检查徽章中的计数是否与数据库中位置的总点赞数匹配。我们还将检查徽章中的计数如何发生变化（增加）。最后，我们将再次模拟点击按钮，以切换回先前的状态。

最后，调用`tearDownClass()`方法，关闭浏览器并从测试数据库中删除位置和超级用户。

# 另请参阅

+   *在第四章*中实现点赞小部件的教程，模板和 JavaScript

+   *使用模拟测试视图*教程

+   *使用 Django REST 框架创建 API 的测试*教程

+   *确保测试覆盖率*教程

# 使用 Django REST 框架创建的 API 的测试

您应该已经了解如何编写单元测试和操作接受测试。在这个教程中，我们将介绍**RESTful API 的组件接口测试**，这是我们在本书中早些时候创建的。

如果您不熟悉 RESTful API 是什么以及 API 的用途，您可以在[`www.restapitutorial.com/`](http://www.restapitutorial.com/)上了解更多。

# 准备工作

让我们从第九章*中的*使用 Django REST 框架创建 API*配方中的`music`应用开始。

# 操作步骤...

要测试 RESTful API，请执行以下步骤：

1.  在`music`应用中创建一个`tests`模块。在`tests`模块中，创建一个名为`test_api.py`的文件，并创建`SongTests`类。该类将具有`setUpClass()`和`tearDownClass()`方法，如下所示：

```py
# myproject/apps/music/tests/test_api.py
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from ..models import Song

class SongTests(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.superuser = User.objects.create_superuser(
            username="admin", password="admin", 
             email="admin@example.com"
        )

        cls.song = Song.objects.create(
            artist="Lana Del Rey",
            title="Video Games - Remastered",
            url="https://open.spotify.com/track/5UOo694cVvj
             cPFqLFiNWGU?si=maZ7JCJ7Rb6WzESLXg1Gdw",
        )

        cls.song_to_delete = Song.objects.create(
            artist="Milky Chance",
            title="Stolen Dance",
            url="https://open.spotify.com/track/3miMZ2IlJ
             iaeSWo1DohXlN?si=g-xMM4m9S_yScOm02C2MLQ",
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

        cls.song.delete()
        cls.superuser.delete()
```

1.  添加一个 API 测试，检查列出歌曲：

```py
    def test_list_songs(self):
        url = reverse("rest_song_list")
        data = {}
        response = self.client.get(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], Song.objects.count())
```

1.  添加一个 API 测试，检查单个歌曲的详细信息：

```py
    def test_get_song(self):
        url = reverse("rest_song_detail", kwargs={"pk": self.song.pk})
        data = {}
        response = self.client.get(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["uuid"], str(self.song.pk))
        self.assertEqual(response.data["artist"], self.song.artist)
        self.assertEqual(response.data["title"], self.song.title)
        self.assertEqual(response.data["url"], self.song.url)
```

1.  添加一个 API 测试，检查成功创建新歌曲：

```py
 def test_create_song_allowed(self):
        # login
        self.client.force_authenticate(user=self.superuser)

        url = reverse("rest_song_list")
        data = {
            "artist": "Capital Cities",
            "title": "Safe And Sound",
            "url": "https://open.spotify.com/track/40Fs0YrUGu
              wLNQSaHGVfqT?si=2OUawusIT-evyZKonT5GgQ",
        }
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, 
         status.HTTP_201_CREATED)

        song = Song.objects.filter(pk=response.data["uuid"])
        self.assertEqual(song.count(), 1)

        # logout
        self.client.force_authenticate(user=None)
```

1.  添加一个尝试在没有身份验证的情况下创建歌曲并因此失败的测试：

```py
 def test_create_song_restricted(self):
        # make sure the user is logged out
        self.client.force_authenticate(user=None)

        url = reverse("rest_song_list")
        data = {
            "artist": "Men I Trust",
            "title": "Tailwhip",
            "url": "https://open.spotify.com/track/2DoO0sn4S
              bUrz7Uay9ACTM?si=SC_MixNKSnuxNvQMf3yBBg",
        }
        response = self.client.post(url, data, format="json")

        self.assertEqual(response.status_code, 
         status.HTTP_403_FORBIDDEN)
```

1.  添加一个检查成功更改歌曲的测试：

```py
def test_change_song_allowed(self):
        # login
        self.client.force_authenticate(user=self.superuser)

        url = reverse("rest_song_detail", kwargs=
         {"pk": self.song.pk})

        # change only title
        data = {
            "artist": "Men I Trust",
            "title": "Tailwhip",
            "url": "https://open.spotify.com/track/2DoO0sn4S
              bUrz7Uay9ACTM?si=SC_MixNKSnuxNvQMf3yBBg",
        }
        response = self.client.put(url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["uuid"], str(self.song.pk))
        self.assertEqual(response.data["artist"], data["artist"])
        self.assertEqual(response.data["title"], data["title"])
        self.assertEqual(response.data["url"], data["url"])

        # logout
        self.client.force_authenticate(user=None)
```

1.  添加一个检查由于缺少身份验证而导致更改失败的测试：

```py
def test_change_song_restricted(self):
        # make sure the user is logged out
        self.client.force_authenticate(user=None)

        url = reverse("rest_song_detail", kwargs=
         {"pk": self.song.pk})

        # change only title
        data = {
            "artist": "Capital Cities",
            "title": "Safe And Sound",
            "url": "https://open.spotify.com/track/40Fs0YrU
             GuwLNQSaHGVfqT?si=2OUawusIT-evyZKonT5GgQ",
        }
        response = self.client.put(url, data, format="json")

        self.assertEqual(response.status_code, 
         status.HTTP_403_FORBIDDEN)
```

1.  添加一个检查歌曲删除失败的测试：

```py
    def test_delete_song_restricted(self):
        # make sure the user is logged out
        self.client.force_authenticate(user=None)

        url = reverse("rest_song_detail", kwargs=
         {"pk": self.song_to_delete.pk})

        data = {}
        response = self.client.delete(url, data, format="json")

        self.assertEqual(response.status_code, 
         status.HTTP_403_FORBIDDEN)
```

1.  添加一个检查成功删除歌曲的测试：

```py
  def test_delete_song_allowed(self):
        # login
        self.client.force_authenticate(user=self.superuser)

        url = reverse("rest_song_detail", kwargs=
         {"pk": self.song_to_delete.pk})

        data = {}
        response = self.client.delete(url, data, format="json")

        self.assertEqual(response.status_code, 
         status.HTTP_204_NO_CONTENT)

        # logout
        self.client.force_authenticate(user=None)
```

1.  运行`music`应用的测试，如下所示：

```py
(env)$python manage.py test myproject.apps.music --settings=myproject.settings.test
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
........
----------------------------------------------------------------------
Ran 8 tests in 0.370s

OK
Destroying test database for alias 'default'...
```

# 它是如何工作的...

这个 RESTful API 测试套件扩展了`APITestCase`类。再次，我们有`setUpClass()`和`tearDownClass()`类方法，它们将在不同测试之前和之后执行。此外，测试套件具有`APIClient`类型的 client 属性，可用于模拟 API 调用。客户端提供所有标准 HTTP 调用的方法：`get()`，`post()`，`put()`，`patch()`，`delete()`，`head()`和`options()`。

在我们的测试中，我们使用`GET`，`POST`和`DELETE`请求。此外，客户端还具有根据登录凭据、令牌或`User`对象强制对用户进行身份验证的方法。在我们的测试中，我们正在进行第三种身份验证：直接将用户传递给`force_authenticate()`方法。

代码的其余部分是不言自明的。

# 另请参阅

+   第九章*中的*使用 Django REST 框架创建 API*配方，导入和导出数据

+   *使用模拟测试视图*配方

+   *使用 Selenium 测试用户界面*配方

+   *确保测试覆盖率*配方

# 确保测试覆盖率

Django 允许快速原型设计和从想法到实现的项目构建。但是，为了确保项目稳定且可用于生产，您应该尽可能多地对功能进行测试。通过测试覆盖率，您可以检查项目代码的测试覆盖率。让我们看看您可以如何做到这一点。

# 准备工作

为您的项目准备一些测试。

在您的虚拟环境中安装`coverage`实用程序：

```py
(env)$ pip install coverage~=5.0.1
```

# 操作步骤...

这是如何检查项目的测试覆盖率的：

1.  为覆盖率实用程序创建一个名为`setup.cfg`的配置文件，内容如下：

```py
# setup.cfg
[coverage:run]
source = .
omit =
    media/*
    static/*
    tmp/*
    drivers/*
    locale/*
    myproject/site_static/*
    myprojext/templates/*
```

1.  如果您使用 Git 版本控制，请确保在`.gitignore`文件中有这些行：

```py
# .gitignore
htmlcov/
.coverage
.coverage.*
coverage.xml
*.cover
```

1.  创建一个名为`run_tests_with_coverage.sh`的 shell 脚本，其中包含运行测试并报告结果的命令：

```py
# run_tests_with_coverage.sh
#!/usr/bin/env bash
coverage erase
coverage run manage.py test --settings=myproject.settings.test
coverage report
```

1.  为该脚本添加执行权限：

```py
(env)$ chmod +x run_tests_with_coverage.sh
```

1.  运行脚本：

```py
(env)$ ./run_tests_with_coverage.sh 
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
...........
----------------------------------------------------------------------
Ran 11 tests in 12.940s

OK
Destroying test database for alias 'default'...
Name Stmts Miss Cover
-----------------------------------------------------------------------------------------------
manage.py 12 2 83%
myproject/__init__.py 0 0 100%
myproject/apps/__init__.py 0 0 100%
myproject/apps/core/__init__.py 0 0 100%
myproject/apps/core/admin.py 16 10 38%
myproject/apps/core/context_processors.py 3 0 100%
myproject/apps/core/model_fields.py 48 48 0%
myproject/apps/core/models.py 87 29 67%
myproject/apps/core/templatetags/__init__.py 0 0 100%
myproject/apps/core/templatetags/utility_tags.py 171 135 21%

the statistics go on…

myproject/settings/test.py 5 0 100%
myproject/urls.py 10 0 100%
myproject/wsgi.py 4 4 0%
-----------------------------------------------------------------------------------------------
TOTAL 1363 712 48%
```

# 它是如何工作的...

覆盖率实用程序运行测试并检查有多少行代码被测试覆盖。在我们的示例中，我们编写的测试覆盖了 48%的代码。如果项目稳定性对您很重要，那么在有时间的时候，尽量接近 100%。

在覆盖配置中，我们跳过了静态资产、模板和其他非 Python 文件。

# 另请参阅

+   *使用模拟测试视图*配方

+   *使用 Selenium 测试用户界面*配方

+   *使用 Django REST 框架创建的 API 进行测试*配方


# 第十二章：部署

在本章中，我们将涵盖以下内容：

+   发布可重用的 Django 应用程序

+   在 Apache 上使用 mod_wsgi 进行暂存环境的部署

+   在 Apache 上使用 mod_wsgi 进行生产环境的部署

+   在 Nginx 和 Gunicorn 上部署暂存环境

+   在生产环境中使用 Nginx 和 Gunicorn 进行部署

# 介绍

一旦您有了一个可用的网站或可重用的应用程序，您就会希望将其公开。部署网站是 Django 开发中最困难的活动之一，因为有许多需要解决的问题：

+   管理 Web 服务器

+   配置数据库

+   提供静态和媒体文件

+   处理 Django 项目

+   配置缓存

+   设置发送电子邮件

+   管理域名

+   安排后台任务和定时作业

+   设置持续集成

+   其他任务，取决于您的项目规模和复杂性

在更大的团队中，所有这些任务都是由 DevOps 工程师完成的，他们需要像深入了解网络和计算机架构、管理 Linux 服务器、bash 脚本编写、使用 vim 等技能。

专业网站通常有**开发**、**暂存**和**生产**环境。它们每个都有特定的目的。开发环境用于创建项目。生产环境是托管公共网站的服务器（或服务器）。暂存环境在技术上类似于生产环境，但用于在发布新功能和优化之前进行检查。

# 技术要求

要使用本章的代码，您需要最新稳定版本的 Python、MySQL 或 PostgreSQL，以及一个带有虚拟环境的 Django 项目。

您可以在 GitHub 存储库的`ch12`目录中找到本章的所有代码，网址为[`github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition`](https://github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition)。

# 发布可重用的 Django 应用程序

Django 文档中有一个关于如何打包可重用应用程序的教程，以便以后可以在任何虚拟环境中使用 pip 进行安装。请访问[`docs.djangoproject.com/en/3.0/intro/reusable-apps/`](https://docs.djangoproject.com/en/3.0/intro/reusable-apps/)​。

然而，还有另一种（可能更好的）打包和发布可重用的 Django 应用程序的方法，使用该工具为不同的编码项目创建模板，例如新的 Django CMS 网站、Flask 网站或 jQuery 插件。其中一个可用的项目模板是`cookiecutter-djangopackage`。在这个教程中，您将学习如何使用它来分发可重用的`likes`应用程序。

# 准备工作

使用虚拟环境创建一个新项目，并在其中安装`cookiecutter`，如下所示：

```py
(env)$ pip install cookiecutter~=1.7.0
```

# 如何做...

要发布您的`likes`应用程序，请按照以下步骤进行：

1.  按照以下步骤启动一个新的 Django 应用项目：

```py
(env)$ cookiecutter https://github.com/pydanny/cookiecutter-djangopackage.git
```

或者，由于这是一个托管在 GitHub 上的`cookiecutter`模板，我们可以使用简写语法，如下所示：

```py
(env)$ cookiecutter gh:pydanny/cookiecutter-djangopackage
```

1.  回答问题以创建应用程序模板，如下所示：

```py
full_name [Your full name here]: Aidas Bendoraitis
email [you@example.com]: aidas@bendoraitis.lt
github_username [yourname]: archatas
project_name [Django Package]: django-likes
repo_name [dj-package]: django-likes
app_name [django_likes]: likes
app_config_name [LikesConfig]: 
project_short_description [Your project description goes here]: Django app for liking anything on your website.
models [Comma-separated list of models]: Like
django_versions [1.11,2.1]: master
version [0.1.0]: 
create_example_project [N]: 
Select open_source_license:
1 - MIT
2 - BSD
3 - ISCL
4 - Apache Software License 2.0
5 - Not open source
Choose from 1, 2, 3, 4, 5 [1]: 
```

这将创建一个基本的文件结构，用于可发布的 Django 包，类似于以下内容：

```py
django-likes/
├── docs/
│   ├── Makefile
│   ├── authors.rst
│   ├── conf.py
│   ├── contributing.rst
│   ├── history.rst
│   ├── index.rst
│   ├── installation.rst
│   ├── make.bat
│   ├── readme.rst
│   └── usage.rst
├── likes/
│   ├── static/
│   │   ├── css/
│   │   │   └── likes.css
│   │   ├── img/
│   │   └── js/
│   │       └── likes.js
│   ├── templates/
│   │   └── likes/
│   │       └── base.html
│   └── test_utils/
│       ├── test_app/
|       │   ├── migrations/
│       │   │   └── __init__.py
│       │   ├── __init__.py
│       │   ├── admin.py
│       │   ├── apps.py
│       │   └── models.html
│       ├── __init__.py
│       ├── admin.py
│       ├── apps.py
│       ├── models.py
│       ├── urls.py
│       └── views.py
├── tests/
│   ├── __init__.py
│   ├── README.md
│   ├── requirements.txt
│   ├── settings.py
│   ├── test_models.py
│   └── urls.py
├── .coveragerc
├── .editorconfig
├── .gitignore
├── .travis.yml
├── AUTHORS.rst
├── CONTRIBUTING.rst
├── HISTORY.rst
├── LICENSE
├── MANIFEST.in
├── Makefile
├── README.rst
├── manage.py
├── requirements.txt
├── requirements_dev.txt
├── requirements_test.txt
├── runtests.py
├── setup.cfg
├── setup.py*
└── tox.ini
```

1.  将`likes`应用程序的文件从您正在使用的 Django 项目复制到`django-likes/likes`目录。在`cookiecutter`创建相同文件的情况下，内容需要合并，而不是覆盖。例如，`likes/__init__.py`文件需要包含一个版本字符串，以便在后续步骤中与`setup.py`正常工作，如下所示：

```py
# django-likes/likes/__init__.py __version__ = '0.1.0'
```

1.  重新安排依赖项，以便不再从 Django 项目导入，并且所有使用的函数和类都在此应用程序内部。例如，在`likes`应用程序中，我们依赖于`core`应用程序中的一些混合。我们需要将相关代码直接复制到`django-likes`应用程序的文件中。

或者，如果有很多依赖代码，我们可以将`core`应用程序作为一个不耦合的包发布，但然后我们必须单独维护它。

1.  将可重用的应用程序项目添加到 GitHub 的 Git 存储库中，使用之前输入的`repo_name`。

1.  浏览不同的文件并完成许可证、`README`、文档、配置和其他文件。

1.  确保应用程序通过`cookiecutter`模板测试：

```py
(env)$ pip install -r requirements_test.txt
(env)$ python runtests.py 
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
.
----------------------------------------------------------------------
Ran 1 test in 0.001s

OK
Destroying test database for alias 'default'...
```

1.  如果您的软件包是闭源的，可以创建一个可共享的 ZIP 存档作为发布，如下所示：

```py
(env)$ python setup.py sdist
```

这将创建一个`django-likes/dist/django-likes-0.1.0.tar.gz`文件，然后可以使用`pip`安装或卸载到任何项目的虚拟环境中，如下所示：

```py
(env)$ pip install django-likes-0.1.0.tar.gz
(env)$ pip uninstall django-likes
```

1.  如果您的软件包是开源的，可以将您的应用程序注册并发布到 Python 包索引(PyPI)： 

```py
(env)$ python setup.py register
(env)$ python setup.py publish
```

1.  此外，为了宣传，通过在[`www.djangopackages.com/packages/add/`](https://www.djangopackages.com/packages/add/)提交表单，将您的应用程序添加到 Django 包中。

# 它是如何工作的...

**Cookiecutter**在 Django 应用程序项目模板的不同部分中填写请求的数据，如果您只是按下*Enter*而不输入任何内容，则使用方括号中给出的默认值。结果，您将得到`setup.py`文件，准备好分发到 Python 包索引、Sphinx 文档、MIT 作为默认许可证、项目的通用文本编辑器配置、包含在您的应用程序中的静态文件和模板，以及其他好东西。

# 另请参阅

+   第一章*, Getting Started with Django 3.0*中的*创建项目文件结构*教程

+   第一章*, Getting Started with Django 3.0*中的*使用 Docker 容器处理 Django、Gunicorn、Nginx 和 PostgreSQL*教程

+   第一章*, Getting Started with Django 3.0*中的*使用 pip 处理项目依赖*教程

+   第四章*, Templates and JavaScript*中的*实现 Like 小部件*教程

+   第十一章*, Testing*中的*使用模拟测试视图*教程

# 在 Apache 上使用 mod_wsgi 进行暂存环境部署

在这个教程中，我将向您展示如何创建一个脚本，将您的项目部署到计算机上的虚拟机上的暂存环境。该项目将使用带有**mod_wsgi**模块的**Apache**网络服务器。对于安装，我们将使用**Ansible**，**Vagrant**和**VirtualBox**。如前所述，有很多细节需要注意，通常需要几天时间来开发类似于此的最佳部署脚本。

# 准备工作

查看部署清单，并确保您的配置符合列在[`docs.djangoproject.com/en/3.0/howto/deployment/checklist/`](https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/)上的所有安全建议。至少确保在运行以下内容时，您的项目配置不会引发警告：

```py
(env)$ python manage.py check --deploy --settings=myproject.settings.staging
```

安装最新稳定版本的 Ansible、Vagrant 和 VirtualBox。您可以从以下官方网站获取它们：

+   **Ansible**: [`docs.ansible.com/ansible/latest/installation_guide/intro_installation.html`](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)

+   **VirtualBox**: [`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)

+   **Vagrant**: [`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html)

在 macOS X 上，您可以使用**HomeBrew**安装它们：

```py
$ brew install ansible
$ brew cask install virtualbox
$ brew cask install vagrant
```

# 如何做...

首先，我们需要为服务器上使用的不同服务创建一些配置模板。暂存和生产部署过程都将使用它们：

1.  在您的 Django 项目中，创建一个`deployment`目录，并在其中创建一个`ansible_templates`目录。

1.  为时区配置创建一个 Jinja 模板文件：

```py
{# deployment/ansible_templates/timezone.j2 #} {{ timezone }}
```

1.  在设置 SSL 证书之前，为 Apache 域配置创建一个 Jinja 模板文件：

```py
{# deployment/ansible_templates/apache_site-pre.conf.j2 #} <VirtualHost *:80>
    ServerName {{ domain_name }}
    ServerAlias {{ domain_name }} www.{{ domain_name }}

    DocumentRoot {{ project_root }}/public_html
    DirectoryIndex index.html

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

    AliasMatch ^/.well-known/(.*) "/var/www/letsencrypt/$1"

    <Directory "/var/www/letsencrypt">
        Require all granted
    </Directory>

    <Directory "/">
        Require all granted
    </Directory>

</VirtualHost>
```

1.  为 Apache 域配置创建一个 Jinja 模板文件`deployment/ansible_templates/apache_site.conf.j2`，还包括 SSL 证书。对于此文件，从[`raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-apache/ansible_templates/apache_site.conf.j2`](https://raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-apache/ansible_templates/apache_site.conf.j2)复制内容。

1.  创建一个用于 PostgreSQL 配置文件`deployment/ansible_templates/postgresql.j2`的模板，内容来自[`github.com/postgres/postgres/blob/REL_10_STABLE/src/backend/utils/misc/postgresql.conf.sample`](https://github.com/postgres/postgres/blob/REL_10_STABLE/src/backend/utils/misc/postgresql.conf.sample)。稍后，您可以在那里调整配置以匹配服务器需求。

1.  创建一个用于 PostgreSQL 权限配置文件的模板（目前非常宽松，但稍后可以根据需要进行调整）：

```py
{# deployment/ansible_templates/pg_hba.j2 #} # TYPE  DATABASE        USER            CIDR-ADDRESS    METHOD
local   all             all                             ident
host    all             all             ::0/0           md5
host    all             all             0.0.0.0/32      md5
host    {{ db_name }}   {{ db_user }}   127.0.0.1/32    md5
```

1.  为 Postfix 电子邮件服务器配置创建一个模板：

```py
{# deployment/ansible_templates/postfix.j2 #} # See /usr/share/postfix/main.cf.dist for a commented, more  
# complete version

# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
# myorigin = /etc/mailname

smtpd_banner = $myhostname ESMTP $mail_name (Ubuntu)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
# delay_warning_time = 4h

readme_directory = no

# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls=yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache

# See /usr/share/doc/postfix/TLS_README.gz in the postfix-doc 
# package for information on enabling SSL in 
# the smtp client.

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = {{ domain_name }}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydestination = $myhostname, localhost, localhost.localdomain, ,  
 localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all
virtual_alias_domains = {{ domain_name }}
virtual_alias_maps = hash:/etc/postfix/virtual
```

1.  创建一个用于电子邮件转发配置的模板：

```py
{# deployment/ansible_templates/virtual.j2 #} # /etc/postfix/virtual

hello@{{ domain_name }} admin@example.com
@{{ domain_name }} admin@example.com
```

1.  创建一个用于`memcached`配置的模板：

```py
{# deployment/ansible_templates/memcached.j2 #} # memcached default config file
# 2003 - Jay Bonci <jaybonci@debian.org>
# This configuration file is read by the start-memcached script 
# provided as part of the Debian GNU/Linux 
# distribution.

# Run memcached as a daemon. This command is implied, and is not
# needed for the daemon to run. See the README.Debian that 
# comes with this package for more information.
-d

# Log memcached's output to /var/log/memcached
logfile /var/log/memcached.log

# Be verbose
# -v

# Be even more verbose (print client commands as well)
# -vv

# Use 1/16 of server RAM for memcached
-m {{ (ansible_memtotal_mb * 0.0625) | int }}

# Default connection port is 11211
-p 11211

# Run the daemon as root. The start-memcached will default to 
# running as root if no -u command is present 
# in this config file
-u memcache

# Specify which IP address to listen on. The default is to 
# listen on all IP addresses
# This parameter is one of the only security measures that 
# memcached has, so make sure it's listening on 
# a firewalled interface.
-l 127.0.0.1

# Limit the number of simultaneous incoming connections. 
# The daemon default is 1024
# -c 1024

# Lock down all paged memory. Consult with the README and 
# homepage before you do this
# -k

# Return error when memory is exhausted (rather than 
# removing items)
# -M

# Maximize core file limit
# -r
```

1.  最后，为`secrets.json`文件创建一个 Jinja 模板：

```py
{# deployment/ansible_templates/secrets.json.j2 #} {
    "DJANGO_SECRET_KEY": "{{ django_secret_key }}",
    "DATABASE_ENGINE": "django.contrib.gis.db.backends.postgis",
    "DATABASE_NAME": "{{ db_name }}",
    "DATABASE_USER": "{{ db_user }}",
    "DATABASE_PASSWORD": "{{ db_password }}",
    "EMAIL_HOST": "{{ email_host }}",
    "EMAIL_PORT": "{{ email_port }}",
    "EMAIL_HOST_USER": "{{ email_host_user }}",
    "EMAIL_HOST_PASSWORD": "{{ email_host_password }}"
} 
```

现在，让我们来处理特定于 staging 环境的 Vagrant 和 Ansible 脚本：

1.  在`.gitignore`文件中，添加忽略一些 Vagrant 和 Ansible 特定文件的行：

```py
# .gitignore # Secrets
secrets.jsonsecrets.yml

# Vagrant / Ansible
.vagrant
*.retry
```

1.  创建两个目录，`deployment/staging`和`deployment/staging/ansible`。

1.  在那里创建一个`Vagrantfile`文件，其中包含以下脚本，用于设置一个带有 Ubuntu 18 的虚拟机，并在其中运行 Ansible 脚本：

```py
# deployment/staging/ansible/Vagrantfile
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "bento/ubuntu-18.04"
  config.vm.box_version = "201912.14.0"
  config.vm.box_check_update = false
  config.ssh.insert_key=false
  config.vm.provider "virtualbox" do |v|
    v.memory = 512
    v.cpus = 1
    v.name = "myproject"
  end
  config.vm.network "private_network", ip: "192.168.50.5"
  config.vm.provision "ansible" do |ansible|
    ansible.limit = "all"
    ansible.playbook = "setup.yml"
    ansible.inventory_path = "./hosts/vagrant"
    ansible.host_key_checking = false
    ansible.verbose = "vv"
    ansible.extra_vars = { ansible_python_interpreter: 
    "/usr/bin/python3" }
  end
end

```

1.  创建一个包含`vagrant`文件的`hosts`目录，其中包含以下内容：

```py
# deployment/staging/ansible/hosts/vagrant
[servers]
192.168.50.5
```

1.  在那里创建一个`vars.yml`文件，其中包含将在安装脚本和 Jinja 模板中使用的变量：

```py
# deployment/staging/ansible/vars.yml
---
# a unix path-friendly name (IE, no spaces or special characters)
project_name: myproject

user_username: "{{ project_name }}"

# the base path to install to. You should not need to change this.
install_root: /home

project_root: "{{ install_root }}/{{ project_name }}"

# the python module path to your project's wsgi file
wsgi_module: myproject.wsgi

# any directories that need to be added to the PYTHONPATH.
python_path: "{{ project_root }}/src/{{ project_name }}"

# the git repository URL for the project
project_repo: git@github.com:archatas/django-myproject.git

# The value of your django project's STATIC_ROOT settings.
static_root: "{{ python_path }}/static"
media_root: "{{ python_path }}/media"

locale: en_US.UTF-8
timezone: Europe/Berlin

domain_name: myproject.192.168.50.5.xip.io
django_settings: myproject.settings.staging

letsencrypt_email: ""
wsgi_file_name: wsgi_staging.py
```

1.  此外，我们还需要一个`secrets.yml`文件，其中包含密码和认证密钥等秘密值。首先，创建一个`sample_secrets.yml`文件，其中不包含敏感信息，只有变量名称，然后将其复制到`secrets.yml`中，并填写秘密信息。前者将受版本控制，而后者将被忽略：

```py
# deployment/staging/ansible/sample_secrets.yml # Django Secret Key
django_secret_key: "change-this-to-50-characters-
 long-random-string"

# PostgreSQL database settings
db_name: "myproject"
db_user: "myproject"
db_password: "change-this-to-a-secret-password"
db_host: "localhost"
db_port: "5432"

# Email SMTP settings
email_host: "localhost"
email_port: "25"
email_host_user: ""
email_host_password: ""

# a private key that has access to the repository URL
ssh_github_key: ~/.ssh/id_rsa_github
```

1.  现在，在`deployment/staging/ansible/setup.yml`创建一个 Ansible 脚本（所谓的*playbook*），用于安装所有依赖项和配置服务。从[`raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-apache/staging/ansible/setup.yml`](https://raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-apache/staging/ansible/setup.yml)复制此文件的内容。

1.  然后在`deployment/staging/ansible/deploy.yml`创建另一个 Ansible 脚本，用于处理 Django 项目。从[`raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-apache/staging/ansible/deploy.yml`](https://raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-apache/staging/ansible/deploy.yml)复制此文件的内容。

1.  并创建一个 bash 脚本，您可以执行以启动部署：

```py
# deployment/staging/ansible/setup_on_virtualbox.sh #!/usr/bin/env bash
echo "=== Setting up the local staging server ==="
date

cd "$(dirname "$0")"
vagrant up --provision
```

1.  为 bash 脚本添加执行权限并运行它：

```py
$ chmod +x setup_on_virtualbox.sh
$ ./setup_on_virtualbox.sh
```

1.  如果脚本出现错误，很可能需要重新启动虚拟机才能生效。您可以通过`ssh`连接到虚拟机，切换到 root 用户，然后按以下步骤重新启动：

```py
$ vagrant ssh
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-72-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information as of Wed Jan 15 04:44:42 CET 2020

 System load:  0.21              Processes:           126
 Usage of /:   4.0% of 61.80GB   Users logged in:     1
 Memory usage: 35%               IP address for eth0: 10.0.2.15
 Swap usage:   4%                IP address for eth1: 192.168.50.5

0 packages can be updated.
0 updates are security updates.

*** System restart required ***

This system is built by the Bento project by Chef Software
More information can be found at https://github.com/chef/bento
Last login: Wed Jan 15 04:43:32 2020 from 192.168.50.1
vagrant@myproject:~$ sudo su
root@myproject:/home/vagrant#
reboot
Connection to 127.0.0.1 closed by remote host.
Connection to 127.0.0.1 closed.
```

1.  要浏览 Django 项目目录，`ssh`到虚拟机并将用户更改为`myproject`

```py
$ vagrant ssh
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-74-generic x86_64)
# … 
vagrant@myproject:~$ sudo su - myproject
(env) myproject@myproject:~$ pwd
/home/myproject
(env) myproject@myproject:~$ ls
commands db_backups logs public_html src env
```

# 工作原理...

VirtualBox 允许您在计算机上拥有多个具有不同操作系统的虚拟机。Vagrant 是一个工具，允许您创建这些虚拟机，并使用脚本下载和安装操作系统。Ansible 是一个基于 Python 的实用程序，它从`.yaml`配置文件中读取指令，并在远程服务器上执行它们。

我们刚刚编写的部署脚本执行以下操作：

+   在 VirtualBox 中创建一个虚拟机并安装 Ubuntu 18

+   将虚拟机的 IP 分配为`192.168.50.5`

+   为虚拟机设置主机名

+   升级 Linux 软件包

+   为服务器设置本地化设置

+   安装所有 Linux 依赖项，包括 Python，Apache，PostgreSQL，Postfix，Memcached 等

+   为 Django 项目创建一个 Linux 用户和`home`目录

+   为 Django 项目创建虚拟环境

+   创建 PostgreSQL 数据库用户和数据库

+   配置 Apache web 服务器

+   安装自签名 SSL 证书

+   配置 Memcached 缓存服务

+   配置 Postfix 邮件服务器

+   克隆 Django 项目存储库

+   安装 Python 依赖项

+   创建`secrets.json`文件

+   迁移数据库

+   收集静态文件

+   重新启动 Apache

现在 Django 网站将可以在`https://www.myproject.192.168.50.5.xip.io`上访问，并显示一个 Hello, World!页面。请注意，一些浏览器，如 Chrome，可能不希望打开具有自签名 SSL 证书的网站，并且会将其作为安全措施进行阻止。

xip.io 是一个通配符 DNS 服务，将特定于 IP 的子域指向 IP，并允许您将其用于 SSL 证书或其他需要域的网站功能。

如果要尝试不同的配置或附加命令，逐步进行小步骤的更改是合理的。对于某些部分，您需要在虚拟机上直接测试，然后再将任务转换为 Ansible 指令。

有关如何使用 Ansible 的信息，请查看官方文档[`docs.ansible.com/ansible/latest/index.html`](https://docs.ansible.com/ansible/latest/index.html)。它显示了大量有用的指令示例，适用于大多数用例。

如果出现任何服务错误，`ssh`到虚拟机，切换到 root 用户，并检查该服务的日志。通过谷歌错误消息可以更接近一个可用的系统。

要重建虚拟机，请使用以下命令：

```py
$ vagrant destroy
$ vagrant up --provision
```

# 另请参阅

+   第一章*, Django 3.0 入门*中的*创建虚拟环境项目文件结构*的步骤

+   第一章*, Django 3.0 入门*中的*使用 pip 处理项目依赖*的步骤

+   第一章**, Django 3.0 入门**中的*为 Git 用户动态设置 STATIC_URL*的步骤

+   *在生产环境中使用 Apache 和 mod_wsgi 部署*的步骤

+   *在暂存环境中使用 Nginx 和 Gunicorn 部署*的步骤

+   *在生产环境中使用 Nginx 和 Gunicorn 部署*的步骤

+   第十三章*, 维护*中的*创建和恢复 PostgreSQL 数据库备份*的步骤

+   第十三章*, 维护*中的*为常规任务设置 cron 作业*的步骤

# 在生产环境中使用 Apache 和 mod_wsgi 部署

Apache 是最流行的 Web 服务器之一。如果您还必须在同一服务器上运行一些需要 Apache 的服务器管理、监控、分析、博客、电子商务等服务，那么将 Django 项目部署在 Apache 下是有意义的。

在本教程中，我们将继续从上一个教程中继续工作，并实现一个 Ansible 脚本（*playbook*），以在**Apache**上使用**mod_wsgi**模块设置生产环境。

# 准备工作

确保在运行以下命令时，项目配置不会引发警告：

```py
(env)$ python manage.py check --deploy -- 
 settings=myproject.settings.production
```

确保您拥有最新的稳定版本的 Ansible。

选择一个服务器提供商，在那里创建一个具有通过 SSH 的根访问权限的专用服务器，并使用私钥和公钥进行身份验证。我选择的提供商是 DigitalOcean（[`www.digitalocean.com/`](https://www.digitalocean.com/)），我在那里创建了一个带有 Ubuntu 18 的专用服务器（Droplet）。我可以通过其 IP`142.93.167.30`连接到服务器，使用新的 SSH 私钥和公钥对`~/.ssh/id_rsa_django_cookbook`和`~/.ssh/id_rsa_django_cookbook.pub`。

在本地，我们需要通过创建或修改`~/.ssh/config`文件来配置 SSH 连接，内容如下：

```py
# ~/.ssh/config
Host *
    ServerAliveInterval 240
    AddKeysToAgent yes
    UseKeychain yes

Host github
    Hostname github.com
    IdentityFile ~/.ssh/id_rsa_github

Host myproject-apache
    Hostname 142.93.167.30
    User root
    IdentityFile ~/.ssh/id_rsa_django_cookbook
```

现在，我们应该能够使用以下命令作为 root 用户通过 SSH 连接到专用服务器：

```py
$ ssh myproject-apache
```

在您的域配置中，将您的域的**DNS A 记录**指向专用服务器的 IP 地址。在我们的情况下，我们将只使用`myproject.142.93.167.30.xip.io`来展示如何为 Django 网站设置服务器的 SSL 证书。

如前所述，xip.io 是一个通配符 DNS 服务，它将特定于 IP 的子域指向 IP，并允许您将其用于需要域的 SSL 证书或其他网站功能。

# 如何操作...

要为生产创建部署脚本，请执行以下步骤：

1.  确保具有我们在上一个*在 Apache 上使用 mod_wsgi 部署到暂存环境*教程中创建的用于服务配置的 Jinja 模板的`deployment/ansible_templates`目录。

1.  为 Ansible 脚本创建`deployment/production`和`deployment/production/ansible`目录。

1.  在那里，创建一个包含以下内容的`hosts`目录和`remote`文件：

```py
# deployment/production/ansible/hosts/remote
[servers]
myproject-apache

[servers:vars]
ansible_python_interpreter=/usr/bin/python3
```

1.  在那里创建一个`vars.yml`文件，其中包含将在安装脚本和 Jinja 模板中使用的变量：

```py
# deployment/production/ansible/vars.yml
---
# a unix path-friendly name (IE, no spaces or special characters)
project_name: myproject

user_username: "{{ project_name }}"

# the base path to install to. You should not need to change this.
install_root: /home

project_root: "{{ install_root }}/{{ project_name }}"

# the python module path to your project's wsgi file
wsgi_module: myproject.wsgi

# any directories that need to be added to the PYTHONPATH.
python_path: "{{ project_root }}/src/{{ project_name }}"

# the git repository URL for the project
project_repo: git@github.com:archatas/django-myproject.git

# The value of your django project's STATIC_ROOT settings.
static_root: "{{ python_path }}/static"
media_root: "{{ python_path }}/media"

locale: en_US.UTF-8
timezone: Europe/Berlin

domain_name: myproject.142.93.167.30.xip.io
django_settings: myproject.settings.production

# letsencrypt settings
letsencrypt_email: hello@myproject.com
wsgi_file_name: wsgi_production.py
```

1.  此外，我们还需要一个`secrets.yml`文件，其中包含密码和身份验证密钥等秘密值。首先创建一个`sample_secrets.yml`文件，其中不包含敏感信息，只有变量名称，然后将其复制到`secrets.yml`并填写秘密信息。前者将受版本控制，而后者将被忽略：

```py
# deployment/production/ansible/sample_secrets.yml # Django Secret Key
django_secret_key: "change-this-to-50-characters-
 long-random-string"

# PostgreSQL database settings
db_name: "myproject"
db_user: "myproject"
db_password: "change-this-to-a-secret-password"
db_host: "localhost"
db_port: "5432"

# Email SMTP settings
email_host: "localhost"
email_port: "25"
email_host_user: ""
email_host_password: ""

# a private key that has access to the repository URL
ssh_github_key: ~/.ssh/id_rsa_github
```

1.  现在，在`deployment/production/ansible/setup.yml`创建一个 Ansible 脚本（*playbook*），用于安装所有依赖项和配置服务。从[`raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-apache/production/ansible/setup.yml`](https://raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-apache/production/ansible/setup.yml)复制此文件的内容。

1.  然后创建另一个 Ansible 脚本，`deployment/production/ansible/deploy.yml`，用于处理 Django 项目。从[`raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-apache/production/ansible/deploy.yml`](https://raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-apache/production/ansible/deploy.yml)复制此文件的内容。

1.  创建一个可以执行以开始部署的 bash 脚本：

```py
# deployment/production/ansible/setup_remotely.sh #!/usr/bin/env bash
echo "=== Setting up the production server ==="
date

cd "$(dirname "$0")"
ansible-playbook setup.yml -i hosts/remote
```

1.  为 bash 脚本添加执行权限并运行它：

```py
$ chmod +x setup_remotely.sh
$ ./setup_remotely.sh
```

1.  如果脚本出现错误，则可能需要重新启动专用服务器才能生效。 您可以通过`ssh`连接到服务器并按以下方式重新启动：

```py
$ ssh myproject-apache
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-74-generic x86_64)

 * Documentation: https://help.ubuntu.com
 * Management: https://landscape.canonical.com
 * Support: https://ubuntu.com/advantage

 System information as of Wed Jan 15 11:39:51 CET 2020

 System load: 0.08 Processes: 104
 Usage of /: 8.7% of 24.06GB Users logged in: 0
 Memory usage: 35% IP address for eth0: 142.93.167.30
 Swap usage: 0%

 * Canonical Livepatch is available for installation.
 - Reduce system reboots and improve kernel security. Activate at:
 https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

*** System restart required ***

Last login: Sun Jan 12 12:23:35 2020 from 178.12.115.146
root@myproject:~# reboot
Connection to 142.93.167.30 closed by remote host.
Connection to 142.93.167.30 closed.
```

1.  创建另一个仅用于更新 Django 项目的 bash 脚本：

```py
# deployment/production/ansible/deploy_remotely.sh #!/usr/bin/env bash
echo "=== Deploying project to production server ==="
date

cd "$(dirname "$0")"
ansible-playbook deploy.yml -i hosts/remote
```

1.  为此 bash 脚本添加执行权限：

```py
$ chmod +x deploy_remotely.sh
```

# 工作原理...

Ansible 脚本（*playbook*）是幂等的。 这意味着您可以多次执行它，您将始终获得相同的结果：安装并运行 Django 网站的最新专用服务器。 如果服务器出现任何技术硬件问题，并且具有数据库和媒体文件的备份，您可以相对快速地在另一个专用服务器上安装相同的配置。

生产部署脚本执行以下操作：

+   为虚拟机设置主机名

+   升级 Linux 软件包

+   为服务器设置本地化设置

+   安装包括 Python、Apache、PostgreSQL、Postfix、Memcached 等在内的所有 Linux 依赖项

+   为 Django 项目创建 Linux 用户和`home`目录

+   为 Django 项目创建虚拟环境

+   创建 PostgreSQL 数据库用户和数据库

+   配置 Apache Web 服务器

+   安装*Let's Encrypt* SSL 证书

+   配置 Memcached 缓存服务

+   配置 Postfix 电子邮件服务器

+   克隆 Django 项目存储库

+   安装 Python 依赖项

+   创建`secrets.json`文件

+   迁移数据库

+   收集静态文件

+   重新启动 Apache

第一次需要安装服务和依赖项时运行`setup_remotely.sh`脚本。 稍后，如果只需要更新 Django 项目，可以使用`deploy_remotely.sh`。 如您所见，安装与暂存服务器上的安装非常相似，但是为了保持灵活性和更易调整，我们将其单独保存在`deployment/production`目录中。

理论上，您可以完全跳过暂存环境，但最好在虚拟机中首先尝试部署过程，而不是直接在远程服务器上进行实验。

# 另请参阅

+   第一章*中的*创建虚拟环境项目文件结构*食谱，开始使用 Django 3.0*

+   第一章*中的*使用 pip 处理项目依赖项*食谱，开始使用 Django 3.0*

+   第一章*中的*为 Git 用户动态设置 STATIC_URL*食谱，开始使用 Django 3.0*

+   *在暂存环境中使用 Apache 和 mod_wsgi 部署*食谱

+   *在暂存环境中使用 Nginx 和 Gunicorn 部署*食谱

+   *在生产环境中使用 Nginx 和 Gunicorn 部署*食谱

+   *创建和恢复 PostgreSQL 数据库备份*食谱

+   *为常规任务设置 cron 作业*食谱

# 在暂存环境中使用 Nginx 和 Gunicorn 进行部署

使用 mod_wsgi 的 Apache 是部署的一个良好且稳定的方法，但是当您需要高性能时，建议使用**Nginx**和**Gunicorn**来为您的 Django 网站提供服务。 Gunicorn 是运行 WSGI 脚本的 Python 服务器。 Nginx 是一个 Web 服务器，它解析域配置并将请求传递给 Gunicorn。

在这个食谱中，我将向您展示如何创建一个脚本，将您的项目部署到计算机上的虚拟机的暂存环境中。 为此，我们将使用**Ansible**，**Vagrant**和**VirtualBox**。 如前所述，需要牢记许多细节，通常需要几天时间来开发类似于此的最佳部署脚本。

# 准备就绪

通过部署清单，确保您的配置通过了[https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/]中的所有安全建议。至少确保在运行以下内容时，您的项目配置不会引发警告：

```py
(env)$ python manage.py check --deploy --
 settings=myproject.settings.staging
```

安装最新稳定版本的 Ansible、Vagrant 和 VirtualBox。您可以从以下官方网站获取它们：

+   **Ansible**：[`docs.ansible.com/ansible/latest/installation_guide/intro_installation.html`](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)

+   **VirtualBox**：[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)

+   **Vagrant**：[`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html)

在 macOS X 上，您可以使用**HomeBrew**安装所有这些：

```py
$ brew install ansible
$ brew cask install virtualbox
$ brew cask install vagrant
```

# 如何做...

首先，我们需要为服务器上使用的不同服务创建一些配置模板。这些将被部署程序使用：分段和生产。

1.  在 Django 项目中，创建一个`deployment`目录，并在其中创建一个`ansible_templates`目录。

1.  为时区配置创建一个 Jinja 模板文件：

```py
{# deployment/ansible_templates/timezone.j2 #} {{ timezone }}
```

1.  在设置 SSL 证书之前，为 Nginx 域配置创建一个 Jinja 模板文件：

```py
{# deployment/ansible_templates/nginx-pre.j2 #} server{
    listen 80;
    server_name {{ domain_name }};

    location /.well-known/acme-challenge {
        root /var/www/letsencrypt;
        try_files $uri $uri/ =404;
    }
    location / {
        root /var/www/letsencrypt;
    }
}

```

1.  在`deployment/ansible_templates/nginx.j2`中为我们的 Nginx 域配置创建一个 Jinja 模板文件，包括 SSL 证书。对于此文件，请从[https://raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-nginx/ansible_templates/nginx.j2]复制内容。

1.  为 Gunicorn 服务配置创建一个模板：

```py
# deployment/ansible_templates/gunicorn.j2
[Unit]
Description=Gunicorn daemon for myproject website
After=network.target

[Service]
PIDFile=/run/gunicorn/pid
Type=simple
User={{ user_username }}
Group=www-data
RuntimeDirectory=gunicorn
WorkingDirectory={{ python_path }}
ExecStart={{ project_root }}/env/bin/gunicorn --pid /run/gunicorn/pid --log-file={{ project_root }}/logs/gunicorn.log --workers {{ ansible_processor_count | int }} --bind 127.0.0.1:8000 {{ project_name }}.wsgi:application --env DJANGO_SETTINGS_MODULE={{ django_settings }} --max-requests 1000
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

1.  在`deployment/ansible_templates/postgresql.j2`中为 PostgreSQL 配置文件创建一个模板，其中包含来自[https://github.com/postgres/postgres/blob/REL_10_STABLE/src/backend/utils/misc/postgresql.conf.sample]的内容。稍后您可以在此文件中调整配置。

1.  为 PostgreSQL 权限配置文件创建一个模板（当前非常宽松，但您可以根据需要稍后进行调整）：

```py
{# deployment/ansible_templates/pg_hba.j2 #} # TYPE  DATABASE        USER            CIDR-ADDRESS    METHOD
local   all             all                             ident
host    all             all             ::0/0           md5
host    all             all             0.0.0.0/32      md5
host    {{ db_name }}   {{ db_user }}   127.0.0.1/32    md5
```

1.  为 Postfix 邮件服务器配置创建一个模板：

```py
{# deployment/ansible_templates/postfix.j2 #} # See /usr/share/postfix/main.cf.dist for a commented, more 
# complete version

# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
# myorigin = /etc/mailname

smtpd_banner = $myhostname ESMTP $mail_name (Ubuntu)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls=yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache

# See /usr/share/doc/postfix/TLS_README.gz in the postfix-doc 
# package for information on enabling SSL 
# in the smtp client.

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = {{ domain_name }}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydestination = $myhostname, localhost, localhost.localdomain, , 
 localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all
virtual_alias_domains = {{ domain_name }}
virtual_alias_maps = hash:/etc/postfix/virtual
```

1.  为电子邮件转发配置创建一个模板：

```py
{# deployment/ansible_templates/virtual.j2 #} # /etc/postfix/virtual

hello@{{ domain_name }} admin@example.com
@{{ domain_name }} admin@example.com
```

1.  为`memcached`配置创建一个模板：

```py
{# deployment/ansible_templates/memcached.j2 #} # memcached default config file
# 2003 - Jay Bonci <jaybonci@debian.org>
# This configuration file is read by the start-memcached script 
# provided as part of the Debian GNU/Linux distribution.

# Run memcached as a daemon. This command is implied, and is not 
# needed for the daemon to run. See the README.Debian 
# that comes with this package for more information.
-d

# Log memcached's output to /var/log/memcached
logfile /var/log/memcached.log

# Be verbose
# -v

# Be even more verbose (print client commands as well)
# -vv

# Use 1/16 of server RAM for memcached
-m {{ (ansible_memtotal_mb * 0.0625) | int }}

# Default connection port is 11211
-p 11211

# Run the daemon as root. The start-memcached will default to 
# running as root if no -u command is present 
# in this config file
-u memcache

# Specify which IP address to listen on. The default is to 
# listen on all IP addresses
# This parameter is one of the only security measures that 
# memcached has, so make sure it's listening 
# on a firewalled interface.
-l 127.0.0.1

# Limit the number of simultaneous incoming connections. The 
# daemon default is 1024
# -c 1024

# Lock down all paged memory. Consult with the README and homepage 
# before you do this
# -k

# Return error when memory is exhausted (rather than 
# removing items)
# -M

# Maximize core file limit
# -r
```

1.  最后，为`secrets.json`文件创建一个 Jinja 模板：

```py
{# deployment/ansible_templates/secrets.json.j2 #} {
    "DJANGO_SECRET_KEY": "{{ django_secret_key }}",
    "DATABASE_ENGINE": "django.contrib.gis.db.backends.postgis",
    "DATABASE_NAME": "{{ db_name }}",
    "DATABASE_USER": "{{ db_user }}",
    "DATABASE_PASSWORD": "{{ db_password }}",
    "EMAIL_HOST": "{{ email_host }}",
    "EMAIL_PORT": "{{ email_port }}",
    "EMAIL_HOST_USER": "{{ email_host_user }}",
    "EMAIL_HOST_PASSWORD": "{{ email_host_password }}"
} 
```

现在让我们来处理针对分段环境的 Vagrant 和 Ansible 脚本：

1.  在`.gitignore`文件中，添加以下行以忽略一些与 Vagrant 和 Ansible 特定的文件：

```py
# .gitignore # Secrets
secrets.jsonsecrets.yml

# Vagrant / Ansible
.vagrant
*.retry
```

1.  创建`deployment/staging`和`deployment/staging/ansible`目录。

1.  在`deployment/staging/ansible`目录中，创建一个`Vagrantfile`文件，其中包含以下脚本，以在其中设置一个带有 Ubuntu 18 的虚拟机并在其中运行 Ansible 脚本：

```py
# deployment/staging/ansible/Vagrantfile
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "bento/ubuntu-18.04"
  config.vm.box_version = "201912.14.0"
  config.vm.box_check_update = false
  config.ssh.insert_key=false
  config.vm.provider "virtualbox" do |v|
    v.memory = 512
    v.cpus = 1
    v.name = "myproject"
  end
  config.vm.network "private_network", ip: "192.168.50.5"
  config.vm.provision "ansible" do |ansible|
    ansible.limit = "all"
    ansible.playbook = "setup.yml"
    ansible.inventory_path = "./hosts/vagrant"
    ansible.host_key_checking = false
    ansible.verbose = "vv"
    ansible.extra_vars = { ansible_python_interpreter: 
    "/usr/bin/python3" }
  end
end

```

1.  创建一个`hosts`目录，其中包含一个`vagrant`文件，其中包含以下内容：

```py
# deployment/staging/ansible/hosts/vagrant
[servers]
192.168.50.5
```

1.  在那里创建一个`vars.yml`文件，其中包含将在安装脚本和 Jinja 模板中使用的变量：

```py
# deployment/staging/ansible/vars.yml
---
# a unix path-friendly name (IE, no spaces or special characters)
project_name: myproject

user_username: "{{ project_name }}"

# the base path to install to. You should not need to change this.
install_root: /home

project_root: "{{ install_root }}/{{ project_name }}"

# the python module path to your project's wsgi file
wsgi_module: myproject.wsgi

# any directories that need to be added to the PYTHONPATH.
python_path: "{{ project_root }}/src/{{ project_name }}"

# the git repository URL for the project
project_repo: git@github.com:archatas/django-myproject.git

# The value of your django project's STATIC_ROOT settings.
static_root: "{{ python_path }}/static"
media_root: "{{ python_path }}/media"

locale: en_US.UTF-8
timezone: Europe/Berlin

domain_name: myproject.192.168.50.5.xip.io
django_settings: myproject.settings.staging

letsencrypt_email: ""
```

1.  我们还需要一个包含秘密值的`secrets.yml`文件，例如密码和身份验证密钥。首先，创建一个`sample_secrets.yml`文件，其中不包含敏感信息，而只包含变量名称，然后将其复制到`secrets.yml`并填写秘密信息。前者将受版本控制，而后者将被忽略：

```py
# deployment/staging/ansible/sample_secrets.yml # Django Secret Key
django_secret_key: "change-this-to-50-characters-long-random-string"

# PostgreSQL database settings
db_name: "myproject"
db_user: "myproject"
db_password: "change-this-to-a-secret-password"
db_host: "localhost"
db_port: "5432"

# Email SMTP settings
email_host: "localhost"
email_port: "25"
email_host_user: ""
email_host_password: ""

# a private key that has access to the repository URL
ssh_github_key: ~/.ssh/id_rsa_github
```

1.  现在在`deployment/staging/ansible/setup.yml`创建一个 Ansible 脚本（*playbook*）以安装所有依赖项并配置服务。从[`raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-nginx/staging/ansible/setup.yml`](https://raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-nginx/staging/ansible/setup.yml)复制此文件的内容。

1.  然后在`deployment/staging/ansible/deploy.yml`创建另一个 Ansible 脚本以处理 Django 项目。从[`raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-nginx/staging/ansible/deploy.yml`](https://raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-nginx/staging/ansible/deploy.yml)复制此文件的内容。

1.  创建一个 bash 脚本，您可以执行以开始部署：

```py
# deployment/staging/ansible/setup_on_virtualbox.sh #!/usr/bin/env bash
echo "=== Setting up the local staging server ==="
date

cd "$(dirname "$0")"
vagrant up --provision
```

1.  为 bash 脚本添加执行权限并运行它：

```py
$ chmod +x setup_on_virtualbox.sh
$ ./setup_on_virtualbox.sh
```

1.  如果脚本出现错误，则可能需要重新启动虚拟机才能生效。您可以通过`ssh`连接到虚拟机，切换到 root 用户，然后按以下步骤重新启动：

```py
$ vagrant ssh
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-72-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information as of Wed Jan 15 04:44:42 CET 2020

 System load:  0.21              Processes:           126
 Usage of /:   4.0% of 61.80GB   Users logged in:     1
 Memory usage: 35%               IP address for eth0: 10.0.2.15
 Swap usage:   4%                IP address for eth1: 192.168.50.5

0 packages can be updated.
0 updates are security updates.

*** System restart required ***

This system is built by the Bento project by Chef Software
More information can be found at https://github.com/chef/bento
Last login: Wed Jan 15 04:43:32 2020 from 192.168.50.1
vagrant@myproject:~$ sudo su
root@myproject:/home/vagrant#
reboot
Connection to 127.0.0.1 closed by remote host.
Connection to 127.0.0.1 closed.
```

1.  浏览 Django 项目目录，`ssh`到虚拟机并将用户更改为`myproject`如下：

```py
$ vagrant ssh
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-74-generic x86_64)
# … 
vagrant@myproject:~$ sudo su - myproject
(env) myproject@myproject:~$ pwd
/home/myproject
(env) myproject@myproject:~$ ls
commands db_backups logs public_html src env
```

# 工作原理...

VirtualBox 允许您在计算机上拥有具有不同操作系统的多个虚拟机。Vagrant 是一个工具，它创建这些虚拟机，并允许您下载和安装操作系统。Ansible 是一个基于 Python 的实用程序，它从`.yaml`配置文件中读取指令，并在远程服务器上执行它们。

我们刚刚编写的部署脚本执行以下操作：

+   在 VirtualBox 中创建一个虚拟机并安装 Ubuntu 18

+   为虚拟机分配 IP`192.168.50.5`

+   为虚拟机设置主机名

+   升级 Linux 软件包

+   为服务器设置本地化设置

+   安装所有 Linux 依赖项，包括 Python、Nginx、PostgreSQL、Postfix、Memcached 等

+   为 Django 项目创建一个 Linux 用户和`home`目录

+   为 Django 项目创建一个虚拟环境

+   创建 PostgreSQL 数据库用户和数据库

+   配置 Nginx Web 服务器

+   安装自签名 SSL 证书

+   配置 Memcached 缓存服务

+   配置 Postfix 邮件服务器

+   克隆 Django 项目存储库

+   安装 Python 依赖项

+   设置 Gunicorn

+   创建`secrets.json`文件

+   迁移数据库

+   收集静态文件

+   重新启动 Nginx

现在 Django 网站将可以在`https://www.myproject.192.168.50.5.xip.io`访问，并显示一个 Hello, World!页面。请注意，包括 Chrome 在内的一些浏览器可能不希望打开具有自签名 SSL 证书的网站，并将其作为安全措施阻止。

xip.io 是一个通配符 DNS 服务，将 IP 特定子域指向 IP，并允许您用于 SSL 证书或其他需要域的网站功能。

如果您想尝试不同的配置或附加命令，逐步以小步骤进行更改是合理的。对于某些部分，您需要在虚拟机上直接测试，然后再将任务转换为 Ansible 指令。

有关如何使用 Ansible 的信息，请查看官方文档[`docs.ansible.com/ansible/latest/index.html`](https://docs.ansible.com/ansible/latest/index.html)。它显示了大多数用例的许多有用的指令示例。

如果您在任何服务中遇到任何错误，请`ssh`到虚拟机，切换到 root 用户，并检查该服务的日志。谷歌错误消息将使您更接近一个可用的系统。

要重建虚拟机，请使用以下命令：

```py
$ vagrant destroy
$ vagrant up --provision
```

# 另请参阅

+   *创建虚拟环境项目文件结构*配方在第一章*，使用 Django 3.0 入门*

+   *使用 pip 处理项目依赖关系*配方在第一章*，使用 Django 3.0 入门*

+   *为 Git 用户动态设置 STATIC_URL*配方在第一章*，使用 Django 3.0 入门*

+   *在 Apache 上使用 mod_wsgi 部署用于暂存环境*配方

+   *在 Apache 上使用 mod_wsgi 部署用于生产环境*配方

+   *在生产环境上使用 Nginx 和 Gunicorn 部署*配方

+   *创建和恢复 PostgreSQL 数据库备份*配方

+   *为常规任务设置 cron 作业*配方

# 在生产环境中使用 Nginx 和 Gunicorn 部署

在这个配方中，我们将继续从上一个配方中工作，并实现一个**Ansible**脚本（playbook）来设置一个带有**Nginx**和**Gunicorn**的生产环境。

# 准备就绪

检查您的项目配置是否在运行以下命令时不会引发警告：

```py
(env)$ python manage.py check --deploy --settings=myproject.settings.production
```

确保使用最新的稳定版本的 Ansible。

选择服务器提供商，并通过私钥和公钥认证创建具有`ssh`根访问权限的专用服务器。我选择的提供商是 DigitalOcean ([`www.digitalocean.com/`](https://www.digitalocean.com/))。在 DigitalOcean 控制面板上，我创建了一个带有 Ubuntu 18 的专用服务器（Droplet）。我可以通过其 IP `46.101.136.102`使用新的 SSH 私钥和公钥对`~/.ssh/id_rsa_django_cookbook`和`~/.ssh/id_rsa_django_cookbook.pub`连接到服务器。

在本地，我们需要通过创建或修改`~/.ssh/config`文件来配置 SSH 连接，内容如下：

```py
# ~/.ssh/config
Host *
    ServerAliveInterval 240
    AddKeysToAgent yes
    UseKeychain yes

Host github
    Hostname github.com
    IdentityFile ~/.ssh/id_rsa_github

Host myproject-nginx
    Hostname 46.101.136.102
    User root
    IdentityFile ~/.ssh/id_rsa_django_cookbook
```

现在我们应该能够使用以下命令作为 root 用户通过`ssh`连接到专用服务器：

```py
$ ssh myproject-nginx
```

在您的域配置中，将您的域的**DNS A 记录**指向专用服务器的 IP 地址。在我们的情况下，我们将只使用`myproject.46.101.136.102.xip.io`来演示如何为 Django 网站设置服务器的 SSL 证书。

# 如何做... 

要为生产创建部署脚本，请执行以下步骤：

1.  确保有一个`deployment/ansible_templates`目录，其中包含我们在前一篇*在暂存环境中使用 Nginx 和 Gunicorn 部署*配方中创建的用于服务配置的 Jinja 模板。

1.  为 Ansible 脚本创建`deployment/production`和`deployment/production/ansible`目录。

1.  创建一个`hosts`目录，其中包含一个包含以下内容的`remote`文件：

```py
# deployment/production/ansible/hosts/remote
[servers]
myproject-nginx

[servers:vars]
ansible_python_interpreter=/usr/bin/python3
```

1.  在那里创建一个`vars.yml`文件，其中包含将在安装脚本和 Jinja 模板中使用的变量：

```py
# deployment/production/ansible/vars.yml
---
# a unix path-friendly name (IE, no spaces or special characters)
project_name: myproject

user_username: "{{ project_name }}"

# the base path to install to. You should not need to change this.
install_root: /home

project_root: "{{ install_root }}/{{ project_name }}"

# the python module path to your project's wsgi file
wsgi_module: myproject.wsgi

# any directories that need to be added to the PYTHONPATH.
python_path: "{{ project_root }}/src/{{ project_name }}"

# the git repository URL for the project
project_repo: git@github.com:archatas/django-myproject.git

# The value of your django project's STATIC_ROOT settings.
static_root: "{{ python_path }}/static"
media_root: "{{ python_path }}/media"

locale: en_US.UTF-8
timezone: Europe/Berlin

domain_name: myproject.46.101.136.102.xip.io
django_settings: myproject.settings.production

# letsencrypt settings
letsencrypt_email: hello@myproject.com
```

1.  我们还需要一个`secrets.yml`文件，其中包含诸如密码和身份验证密钥之类的秘密值。首先，创建一个`sample_secrets.yml`文件，其中不包含敏感信息，而只包含变量名称，然后将其复制到`secrets.yml`并填写秘密信息。前者将受版本控制，而后者将被忽略：

```py
# deployment/production/ansible/sample_secrets.yml # Django Secret Key
django_secret_key: "change-this-to-50-characters-long-random-string"

# PostgreSQL database settings
db_name: "myproject"
db_user: "myproject"
db_password: "change-this-to-a-secret-password"
db_host: "localhost"
db_port: "5432"

# Email SMTP settings
email_host: "localhost"
email_port: "25"
email_host_user: ""
email_host_password: ""

# a private key that has access to the repository URL
ssh_github_key: ~/.ssh/id_rsa_github
```

1.  现在在`deployment/production/ansible/setup.yml`创建一个 Ansible 脚本（*playbook*）以安装所有依赖项并配置服务。从[`raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-nginx/production/ansible/setup.yml`](https://raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-nginx/production/ansible/setup.yml)复制此文件的内容。

1.  然后在`deployment/production/ansible/deploy.yml`创建另一个 Ansible 脚本以处理 Django 项目。从[`raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-nginx/production/ansible/deploy.yml`](https://raw.githubusercontent.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition/master/ch12/myproject_virtualenv/src/django-myproject/deployment-nginx/production/ansible/deploy.yml)复制此文件的内容。

1.  创建一个 bash 脚本，您可以执行以开始部署：

```py
# deployment/production/ansible/setup_remotely.sh #!/usr/bin/env bash
echo "=== Setting up the production server ==="
date

cd "$(dirname "$0")"
ansible-playbook setup.yml -i hosts/remote
```

1.  为 bash 脚本添加执行权限并运行它：

```py
$ chmod +x setup_remotely.sh
$ ./setup_remotely.sh
```

1.  如果脚本出现错误，很可能是专用服务器需要重新启动才能生效。您可以通过`ssh`连接到服务器并按以下方式重新启动来执行此操作：

```py
$ ssh myproject-nginx
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-74-generic x86_64)

 * Documentation: https://help.ubuntu.com
 * Management: https://landscape.canonical.com
 * Support: https://ubuntu.com/advantage

 System information as of Wed Jan 15 11:39:51 CET 2020

 System load: 0.08 Processes: 104
 Usage of /: 8.7% of 24.06GB Users logged in: 0
 Memory usage: 35% IP address for eth0: 142.93.167.30
 Swap usage: 0%

 * Canonical Livepatch is available for installation.
 - Reduce system reboots and improve kernel security. Activate at:
 https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

*** System restart required ***

Last login: Sun Jan 12 12:23:35 2020 from 178.12.115.146
root@myproject:~# reboot
Connection to 142.93.167.30 closed by remote host.
Connection to 142.93.167.30 closed.
```

1.  创建另一个仅用于更新 Django 项目的 bash 脚本：

```py
# deployment/production/ansible/deploy_remotely.sh #!/usr/bin/env bash
echo "=== Deploying project to production server ==="
date

cd "$(dirname "$0")"
ansible-playbook deploy.yml -i hosts/remote
```

1.  为 bash 脚本添加执行权限：

```py
$ chmod +x deploy_remotely.sh
```

# 它是如何工作的...

Ansible 脚本（*playbook*）是幂等的。这意味着您可以多次执行它，您将始终获得相同的结果，即安装并运行 Django 网站的最新专用服务器。如果服务器出现任何技术硬件问题，并且有数据库和媒体文件的备份，您可以相对快速地在另一个专用服务器上安装相同的配置。

生产部署脚本执行以下操作：

+   为虚拟机设置主机名

+   升级 Linux 软件包

+   为服务器设置本地化设置

+   安装所有 Linux 依赖项，如 Python、Nginx、PostgreSQL、Postfix、Memcached 等

+   为 Django 项目创建 Linux 用户和`home`目录

+   为 Django 项目创建虚拟环境

+   创建 PostgreSQL 数据库用户和数据库

+   配置 Nginx Web 服务器

+   安装*Let's Encrypt* SSL 证书

+   配置 Memcached 缓存服务

+   配置 Postfix 邮件服务器

+   克隆 Django 项目存储库

+   安装 Python 依赖项

+   设置 Gunicorn

+   创建`secrets.json`文件

+   迁移数据库

+   收集静态文件

+   重新启动 Nginx

如您所见，安装与暂存服务器上的安装非常相似，但是为了保持灵活性和更易调整，我们将其分别保存在`deployment/production`目录中。

理论上，您可以完全跳过暂存环境，但是在虚拟机中尝试部署过程比直接在远程服务器上进行实验更实际。

# 另请参阅

+   *在第一章*《使用 Django 3.0 入门》中的*创建虚拟环境项目文件结构*配方

+   *在第一章*《使用 Django 3.0 入门》中的*使用 pip 处理项目依赖项*配方

+   *在第一章*《使用 Django 3.0 入门》中的*为 Git 用户动态设置 STATIC_URL*配方

+   *在 Apache 上使用 mod_wsgi 部署暂存环境*配方

+   *在生产环境中使用 Apache 和 mod_wsgi 部署*配方

+   *在 Nginx 和 Gunicorn 上部署暂存环境*配方

+   *创建和恢复 PostgreSQL 数据库备份*配方

+   *为常规任务设置 cron 作业*配方
