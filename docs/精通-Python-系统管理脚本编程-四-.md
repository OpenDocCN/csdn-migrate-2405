# 精通 Python 系统管理脚本编程（四）

> 原文：[`zh.annas-archive.org/md5/c33d6613eafa4d86b92059a00f7aa16f`](https://zh.annas-archive.org/md5/c33d6613eafa4d86b92059a00f7aa16f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：网络爬虫-从网站提取有用的数据

在本章中，您将学习有关网络爬虫的知识。您还将学习 Python 中的`beautifulsoup`库，该库用于从网站提取信息。

在本章中，我们将涵盖以下主题：

+   什么是网络爬虫？

+   数据提取

+   从维基百科提取信息

# 什么是网络爬虫？

网络爬虫是从网站提取信息的技术。这种技术用于将非结构化数据转换为结构化数据。

网络爬虫的用途是从网站提取数据。提取的信息以本地文件的形式保存在您的系统上，您也可以以表格格式将其存储到数据库中。网络爬虫软件直接使用 HTTP 或 Web 浏览器访问**万维网**（**WWW**）。这是使用网络爬虫或机器人实施的自动化过程。

爬取网页涉及获取页面，然后提取数据。网络爬虫获取网页。网络爬虫是网络爬取中的一个必不可少的组件。获取后，进行提取。您可以搜索、解析、将数据保存到表中，并重新格式化页面。

# 数据提取

在本节中，我们将看到实际的数据提取过程。Python 具有`beautifulsoup`库来执行数据提取任务。我们还将使用 Python 的 requests 库。

首先，我们必须安装这两个库。运行以下命令以安装`requests`和`beautifulsoup`库：

```py
$ pip3 install requests $ pip3 install beautifulsoup4
```

# requests 库

使用`requests`库是在我们的 Python 脚本中以人类可读的格式使用 HTTP。我们可以使用 Python 中的`requests`库下载页面。`requests`库有不同类型的请求。在这里，我们将学习`GET`请求。`GET`请求用于从 Web 服务器检索信息。`GET`请求下载指定网页的 HTML 内容。每个请求都有一个状态代码。状态代码与我们向服务器发出的每个请求一起返回。这些状态代码为我们提供了关于请求发生了什么的信息。状态代码的类型在此列出：

+   `200`：表示一切正常，并返回结果（如果有的话）

+   `301`：表示服务器正在重定向到不同的端点，如果已经切换了域名或端点名称必须更改

+   `400`：表示您发出了一个错误的请求

+   `401`：表示我们未经授权

+   `403`：表示您正在尝试访问被禁止的资源

+   `404`：表示您正在尝试访问的资源在服务器上不可用

# beautifulsoup 库

`beautifulsoup`是 Python 中用于网络爬虫的库。它具有用于搜索、导航和修改的简单方法。它只是一个工具包，用于从网页中提取所需的数据。

现在，要在脚本中使用`requests`和`beautifulsoup`功能，您必须使用`import`语句导入这两个库。现在，我们将看一个解析网页的例子。在这里，我们将解析一个网页，这是来自 IMDb 网站的头条新闻页面。为此，请创建一个`parse_web_page.py`脚本，并在其中编写以下内容：

```py
import requests from bs4 import BeautifulSoup page_result = requests.get('https://www.imdb.com/news/top?ref_=nv_nw_tp') parse_obj = BeautifulSoup(page_result.content, 'html.parser') print(parse_obj)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 parse_web_page.py Output: <!DOCTYPE html> <html  > <head> <meta charset="utf-8"/> <meta content="IE=edge" http-equiv="X-UA-Compatible"/> <meta content="app-id=342792525, app-argument=imdb:///?src=mdot" name="apple-itunes-app"/> <script type="text/javascript">var IMDbTimer={starttime: new Date().getTime(),pt:'java'};</script> <script>
 if (typeof uet == 'function') { uet("bb", "LoadTitle", {wb: 1}); } </script> <script>(function(t){ (t.events = t.events || {})["csm_head_pre_title"] = new Date().getTime(); })(IMDbTimer);</script> <title>Top News - IMDb</title> <script>(function(t){ (t.events = t.events || {})["csm_head_post_title"] = new Date().getTime(); })(IMDbTimer);</script> <script>
 if (typeof uet == 'function') { uet("be", "LoadTitle", {wb: 1}); } </script> <script>
 if (typeof uex == 'function') { uex("ld", "LoadTitle", {wb: 1}); } </script> <link href="https://www.imdb.com/news/top" rel="canonical"/> <meta content="http://www.imdb.com/news/top" property="og:url"> <script>
 if (typeof uet == 'function') { uet("bb", "LoadIcons", {wb: 1}); }
```

在前面的示例中，我们收集了一个页面并使用`beautifulsoup`解析了它。首先，我们导入了`requests`和`beautifulsoup`模块。然后，我们使用`GET`请求收集了 URL，并将该 URL 分配给`page_result`变量。接下来，我们创建了一个`beautifulsoup`对象`parse_obj`。这个对象将使用来自 requests 的`page_result`.content 作为参数，然后使用`html.parser`解析页面。

现在，我们将从一个类和一个标签中提取内容。要执行此操作，请转到您的网络浏览器，右键单击要提取的内容，然后向下滚动，直到您看到**检查**选项。单击它，您将获得类名。在程序中提到它并运行您的脚本。为此，请创建一个`extract_from_class.py`脚本，并在其中编写以下内容：

```py
import requests from bs4 import BeautifulSoup page_result = requests.get('https://www.imdb.com/news/top?ref_=nv_nw_tp') parse_obj = BeautifulSoup(page_result.content, 'html.parser') top_news = parse_obj.find(class_='news-article__content') print(top_news)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 extract_from_class.py Output : <div class="news-article__content"> <a href="/name/nm4793987/">Issa Rae</a> and <a href="/name/nm0000368/">Laura Dern</a> are teaming up to star in a limited series called “The Dolls” currently in development at <a href="/company/co0700043/">HBO</a>.<br/><br/>Inspired by true events, the series recounts the aftermath of Christmas Eve riots in two small Arkansas towns in 1983, riots which erupted over Cabbage Patch Dolls. The series explores class, race, privilege and what it takes to be a “good mother.”<br/><br/>Rae will serve as a writer and executive producer on the series in addition to starring, with Dern also executive producing. <a href="/name/nm3308450/">Laura Kittrell</a> and <a href="/name/nm4276354/">Amy Aniobi</a> will also serve as writers and co-executive producers. <a href="/name/nm0501536/">Jayme Lemons</a> of Dern’s <a href="/company/co0641481/">Jaywalker Pictures</a> and <a href="/name/nm3973260/">Deniese Davis</a> of <a href="/company/co0363033/">Issa Rae Productions</a> will also executive produce.<br/><br/>Both Rae and Dern currently star in HBO shows, with Dern appearing in the acclaimed drama “<a href="/title/tt3920596/">Big Little Lies</a>” and Rae starring in and having created the hit comedy “<a href="/title/tt5024912/">Insecure</a>.” Dern also recently starred in the film “<a href="/title/tt4015500/">The Tale</a>,
 </div>
```

在上面的例子中，我们首先导入了 requests 和`beautifulsoup`模块。然后，我们创建了一个请求对象并为其分配了一个 URL。接下来，我们创建了一个`beautifulsoup`对象`parse_obj`。这个对象以 requests 的`page_result.content`作为参数，然后使用`html.parser`解析页面。接下来，我们使用 beautifulsoup 的`find()`方法从`'news-article__content'`类中获取内容。

现在，我们将看到从特定标签中提取内容的示例。在这个例子中，我们将从`<a>`标签中提取内容。创建一个`extract_from_tag.py`脚本，并在其中编写以下内容：

```py
import requests from bs4 import BeautifulSoup page_result = requests.get('https://www.imdb.com/news/top?ref_=nv_nw_tp') parse_obj = BeautifulSoup(page_result.content, 'html.parser') top_news = parse_obj.find(class_='news-article__content') top_news_a_content = top_news.find_all('a') print(top_news_a_content)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 extract_from_tag.py Output: [<a href="/name/nm4793987/">Issa Rae</a>, <a href="/name/nm0000368/">Laura Dern</a>, <a href="/company/co0700043/">HBO</a>, <a href="/name/nm3308450/">Laura Kittrell</a>, <a href="/name/nm4276354/">Amy Aniobi</a>, <a href="/name/nm0501536/">Jayme Lemons</a>, <a href="/company/co0641481/">Jaywalker Pictures</a>, <a href="/name/nm3973260/">Deniese Davis</a>, <a href="/company/co0363033/">Issa Rae Productions</a>, <a href="/title/tt3920596/">Big Little Lies</a>, <a href="/title/tt5024912/">Insecure</a>, <a href="/title/tt4015500/">The Tale</a>]
```

在上面的例子中，我们正在从`<a>`标签中提取内容。我们使用`find_all()`方法从`'news-article__content'`类中提取所有`<a>`标签内容。

# 从维基百科中提取信息

在本节中，我们将看到维基百科上興舞形式列表的一个示例。我们将列出所有古典印度舞蹈。为此，请创建一个`extract_from_wikipedia.py`脚本，并在其中编写以下内容：

```py
import requests from bs4 import BeautifulSoup page_result = requests.get('https://en.wikipedia.org/wiki/Portal:History') parse_obj = BeautifulSoup(page_result.content, 'html.parser') h_obj = parse_obj.find(class_='hlist noprint')
h_obj_a_content = h_obj.find_all('a') print(h_obj) print(h_obj_a_content)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 extract_from_wikipedia.py
Output:
<div class="hlist noprint" id="portals-browsebar" style="text-align: center;">
<dl><dt><a href="/wiki/Portal:Contents/Portals" title="Portal:Contents/Portals">Portal topics</a></dt>
<dd><a href="/wiki/Portal:Contents/Portals#Human_activities" title="Portal:Contents/Portals">Activities</a></dd>
<dd><a href="/wiki/Portal:Contents/Portals#Culture_and_the_arts" title="Portal:Contents/Portals">Culture</a></dd>
<dd><a href="/wiki/Portal:Contents/Portals#Geography_and_places" title="Portal:Contents/Portals">Geography</a></dd>
<dd><a href="/wiki/Portal:Contents/Portals#Health_and_fitness" title="Portal:Contents/Portals">Health</a></dd>
<dd><a href="/wiki/Portal:Contents/Portals#History_and_events" title="Portal:Contents/Portals">History</a></dd>
<dd><a href="/wiki/Portal:Contents/Portals#Mathematics_and_logic" title="Portal:Contents/Portals">Mathematics</a></dd>
<dd><a href="/wiki/Portal:Contents/Portals#Natural_and_physical_sciences" title="Portal:Contents/Portals">Nature</a></dd>
<dd><a href="/wiki/Portal:Contents/Portals#People_and_self" title="Portal:Contents/Portals">People</a></dd>
In the preceding example, we extracted the content from Wikipedia. In this example also, we extracted the content from class as well as tag.
....
```

# 摘要

在本章中，您了解了网络爬取的内容。我们了解了用于从网页中提取数据的两个库。我们还从维基百科中提取了信息。

在下一章中，您将学习有关统计数据收集和报告的内容。您将学习有关 NumPy 模块、数据可视化以及使用图表、图形和图表显示数据的内容。

# 问题

1.  什么是网络爬虫？

1.  什么是网络爬虫？

1.  您能够在登录页面后面抓取数据吗？

1.  你能爬 Twitter 吗？

1.  是否可能抓取 JavaScript 页面？如果是，如何？

# 进一步阅读

+   Urllib 文档：[`docs.python.org/3/library/urllib.html`](https://docs.python.org/3/library/urllib.html)

+   Mechanize：[`mechanize.readthedocs.io/en/latest/`](https://mechanize.readthedocs.io/en/latest/)

+   Scrapemark：[`pypi.org/project/scrape/`](https://pypi.org/project/scrape/)

+   Scrapy：[`doc.scrapy.org/en/latest/index.html`](https://doc.scrapy.org/en/latest/index.html)


# 第十七章：统计数据收集和报告

在本章中，您将学习有关用于科学计算的统计学中使用的高级 Python 库。您将学习有关 Python 的 NumPY、Pandas、Matplotlib 和 Plotly 模块。您将学习有关数据可视化技术，以及如何绘制收集到的数据。

在本章中，我们将涵盖以下主题：

+   NumPY 模块

+   Pandas 模块

+   数据可视化

# NumPY 模块

NumPY 是一个提供数组高效操作的 Python 模块。NumPY 是 Python 科学计算的基本包。这个包通常用于 Python 数据分析。NumPY 数组是多个值的网格。

通过在终端中运行以下命令来安装 NumPY：

```py
$ pip3 install numpy
```

我们将使用`numpy`库对`numpy`数组进行操作。现在我们将看看如何创建`numpy`数组。为此，请创建一个名为`simple_array.py`的脚本，并在其中编写以下代码：

```py
import numpy as np my_list1 = [1,2,3,4] my_array1 = np.array(my_list1) print(my_list11, type(my_list1))
print(my_array1, type(my_array1))
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~$ python3 simple_array.py
```

输出如下：

```py
[1, 2, 3, 4] <class 'list'>
[1 2 3 4] <class 'numpy.ndarray'>
```

在前面的例子中，我们导入了`numpy`库作为`np`来使用`numpy`的功能。然后我们创建了一个简单的列表，将其转换为数组，我们使用了**`np.array()`**函数**。**最后，我们打印了带有类型的`numpy`数组，以便更容易理解普通数组和`numpy`数组。

上一个例子是单维数组的例子。现在我们将看一个多维数组的例子。为此，我们必须创建另一个列表。让我们看另一个例子。创建一个名为`mult_dim_array.py`的脚本，并在其中编写以下内容：

```py
import numpy as np my_list1 = [1,2,3,4] my_list2 = [11,22,33,44] my_lists = [my_list1, my_list2]
my_array = np.array(my_lists)
print(my_lists, type(my_lists)) print(my_array, type(my_array))
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~$ python3 mult_dim_array.py
```

输出如下：

```py
[[1, 2, 3, 4], [11, 22, 33, 44]] <class 'list'>
[[ 1 2 3 4]
 [11 22 33 44]] <class 'numpy.ndarray'>
```

在前面的例子中，我们导入了`numpy`模块。之后，我们创建了两个列表：`my_list1`和`my_list2`。然后我们创建了另一个列表的列表（`my_list1`和`my_list2`），并在列表（`my_lists`）上应用了`np.array()`函数，并将其存储在一个名为`my_array`的对象中。最后，我们打印了`numpy`数组。

现在，我们将看一下可以对数组进行的更多操作。我们将学习如何知道我们创建的数组`my_array`的大小和数据类型；也就是说，应用`shape()`函数我们将得到数组的`size`，应用`dtype()`函数我们将知道数组的`数据类型`。让我们看一个例子。创建一个名为`size_and_dtype.py`的脚本，并在其中编写以下内容：

```py
import numpy as np my_list1 = [1,2,3,4] my_list2 = [11,22,33,44] my_lists = [my_list1,my_list2] my_array = np.array(my_lists) print(my_array) size = my_array.shape print(size) data_type = my_array.dtype print(data_type)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~$ python3 size_and_dtype.py
```

输出如下：

```py
[[ 1  2  3  4]
 [11 22 33 44]] (2, 4) int64
```

在前面的例子中，我们应用了`shape`函数`my_array.shape`来获取数组的大小。输出是`(2, 4)`。然后我们在数组上应用了`dtype`函数`my_array.dtype`，输出是`int64`**。**

现在，我们将看一些特殊情况数组的例子。

首先，我们将使用`np.zeros()`函数创建一个所有值为零的数组，如下所示：

```py
student@ubuntu:~$ python3 Python 3.6.7 (default, Oct 22 2018, 11:32:17) [GCC 8.2.0] on linux Type "help", "copyright", "credits" or "license" for more information. >>> import numpy as np >>> np.zeros(5) array([0., 0., 0., 0., 0.]) >>> 
```

在创建所有值为零的数组之后，我们将使用`numpy`的`np.ones()`函数创建所有值为 1 的数组，如下所示：

```py
>>> np.ones((5,5)) array([[1., 1., 1., 1., 1.],
 [1., 1., 1., 1., 1.], [1., 1., 1., 1., 1.], [1., 1., 1., 1., 1.], [1., 1., 1., 1., 1.]]) >>> 
```

`np.ones((5,5))`创建一个所有值为`1`的`5*5`数组。

现在，我们将使用`numpy`的`np.empty()`函数创建一个空数组，如下所示：

```py
>>> np.empty([2,2]) array([[6.86506982e-317,  0.00000000e+000],
 [6.89930557e-310,  2.49398949e-306]]) >>> 
```

`np.empty()`不会像`np.zeros()`函数一样将数组值设置为零。因此，它可能更快。此外，它要求用户在数组中手动输入所有值，因此应谨慎使用。

现在，让我们看看如何使用`np.eye()`函数创建一个对角线值为`1`的单位矩阵，如下所示：

```py
>>> np.eye(5) array([[1., 0., 0., 0., 0.],
 [0., 1., 0., 0., 0.], [0., 0., 1., 0., 0.], [0., 0., 0., 1., 0.], [0., 0., 0., 0., 1.]]) >>> 
```

现在，我们将看一下`range`函数，它用于使用`numpy`的`np.arange()`函数创建数组，如下所示：

```py
>>> np.arange(10) array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]) >>> 
```

`np.arange(10)`函数创建了范围为`0-9`的数组。我们定义了范围值`10`，因此数组索引值从`0`开始。

# 使用数组和标量

在这一部分，我们将看一下使用`numpy`进行数组的各种算术运算。首先，我们将创建一个多维数组，如下所示：

```py
student@ubuntu:~$ python3 Python 3.6.7 (default, Oct 22 2018, 11:32:17) [GCC 8.2.0] on linux Type "help", "copyright", "credits" or "license" for more information. >>> import numpy as np >>> from __future__ import division >>> arr = np.array([[4,5,6],[7,8,9]]) >>> arr array([[4, 5, 6],
 [7, 8, 9]]) >>> 
```

在这里，我们导入了`numpy`模块来使用`numpy`的功能，然后我们导入了`__future__`模块，它将处理浮点数。之后，我们创建了一个二维数组`arr`，对其进行各种操作。

现在，让我们看一下对数组的一些算术运算。首先，我们将学习数组的乘法，如下所示：

```py
>>> arr*arr array([[16, 25, 36],
 [49, 64, 81]]) >>> 
```

在上面的乘法操作中，我们将`arr`数组乘以两次以得到一个乘法数组。您也可以将两个不同的数组相乘。

现在，我们将看一下对数组进行减法操作，如下所示：

```py
>>> arr-arr array([[0, 0, 0],
 [0, 0, 0]]) >>> 
```

如前面的例子所示，我们只需使用`**-**`运算符来对两个数组进行减法。在减法操作之后，我们得到了结果数组，如前面的代码所示。

现在我们将看一下对标量进行数组的算术运算。让我们看一些操作：

```py
>>> 1 / arr array([[0.25             ,  0.2        ,   0.16666667],
 [0.14285714 ,   0.125     ,  0.11111111]]) >>> 
```

在上面的例子中，我们将`1`除以我们的数组并得到了输出。请记住，我们导入了`__future__`模块，它实际上对这样的操作非常有用，可以处理数组中的浮点值。

现在我们将看一下`numpy`数组的指数运算，如下所示：

```py
>>> arr ** 3 array([[ 64, 125, 216],
 [343, 512, 729]]) >>> 
```

在上面的例子中，我们对数组取了立方，并得到了每个值的立方作为输出。

# 数组索引

使用数组作为索引来对数组进行索引。使用索引数组，将返回原始数组的副本。`numpy`数组可以使用任何其他序列或使用任何其他数组进行索引，但不包括元组。数组中的最后一个元素可以通过`-1`进行索引，倒数第二个元素可以通过`-2`进行索引，依此类推。

因此，要对数组进行索引操作，首先我们创建一个新的`numpy`数组，为此我们将使用`range()`函数来创建数组，如下所示：

```py
student@ubuntu:~$ python3 Python 3.6.7 (default, Oct 22 2018, 11:32:17) [GCC 8.2.0] on linux Type "help", "copyright", "credits" or "license" for more information. >>> import numpy as np >>> arr = np.arange(0,16) >>> arr array([ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15]) >>> 
```

在上面的例子中，我们创建了范围为`16`（即`0-15`）的数组`arr`。

现在，我们将对数组`arr`执行不同的索引操作。首先，让我们获取数组中特定索引处的值：

```py
>>> arr[7] 7 >>> 
```

在上面的例子中，我们通过其索引值访问了数组，并在将索引号传递给数组`arr`后，数组返回了值`7`，这是我们传递的特定索引号。

在获取特定索引处的值之后，我们将获取一定范围内的值。让我们看下面的例子：

```py
>>> arr[2:10] array([2, 3, 4, 5, 6, 7, 8, 9]) >>> arr[2:10:2] array([2, 4, 6, 8])>>>
```

在上面的例子中，首先我们访问了数组并得到了范围为（`2-10`）的值。结果显示为`array([2, 3, 4, 5, 6, 7, 8, 9])`。在第二个术语中，`arr[2:10:2]`，实际上是指定在范围`2-10`内以两步的间隔访问数组。这种索引的语法是`arr[_start_value_:_stop_value_:_steps_]`。因此，第二个术语的输出是`array([2, 4, 6, 8])`。

我们还可以从索引值开始获取数组中的值直到末尾，如下例所示：

```py
>>> arr[5:] array([ 5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15]) >>> 
```

正如我们在上面的例子中看到的，我们从第 5 个索引值开始访问数组中的值直到末尾。结果，我们得到的输出是`array([ 5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15])`。

现在我们将看一下`numpy`数组的切片。在切片中，我们实际上是取原始数组的一部分并将其存储在指定的数组名称中。让我们看一个例子：

```py
>>> arr_slice = arr[0:8] >>> arr_slice array([0, 1, 2, 3, 4, 5, 6, 7]) >>> 
```

在上面的例子中，我们对原始数组进行了切片。结果，我们得到了一个包含值`0,1,2,…..,7`的数组切片。我们还可以给数组切片赋予更新后的值。让我们看一个例子：

```py
>>> arr_slice[:] = 29 >>> arr_slice array([29, 29, 29, 29, 29, 29, 29, 29]) >>> 
```

在前面的例子中，我们将数组切片中的所有值设置为`29`。但在为数组切片分配值时，重要的是分配给切片的值也将分配给数组的原始集合。

让我们看看给数组的切片赋值后的结果，以及对我们原始数组的影响：

```py
>>> arr array([29, 29, 29, 29, 29, 29, 29, 29,  8,  9, 10, 11, 12, 13, 14, 15]) >>>
```

现在，我们将看另一个操作；即，复制数组。对数组进行切片和复制的区别在于，当我们对数组进行切片时，所做的更改将应用于原始数组。当我们获得数组的副本时，它会给出原始数组的显式副本。因此，对数组的副本应用的更改不会影响原始数组。所以让我们看一个复制数组的例子：

```py
>>> cpying_arr = arr.copy() >>> cpying_arr array([29, 29, 29, 29, 29, 29, 29, 29,  8,  9, 10, 11, 12, 13, 14, 15]) >>> 
```

在前面的例子中，我们只是复制了原始数组。为此，我们使用了`array_name.copy()`函数，输出是原始数组的副本。

# 对二维数组进行索引

二维数组是一个数组的数组。在这种情况下，数据元素的位置通常是指两个索引而不是一个，并且它表示具有行和列数据的表。现在我们将对这种类型的数组进行索引。

所以，让我们来看一个二维数组的例子：

```py
>>> td_array = np.array(([5,6,7],[8,9,10],[11,12,13])) >>> td_array array([[  5,   6,    7],
 [  8,   9,  10], [11, 12,  13]]) >>> 
```

在前面的例子中，我们创建了一个名为`td_array`的二维数组。创建数组后，我们打印了`td_array`。现在我们还将通过索引获取`td_array`中的值。让我们看一个通过索引访问值的例子：

```py
>>> td_array[1] array([ 8,  9, 10]) >>>
```

在前面的例子中，我们访问了数组的第一个索引值，并得到了输出。在这种类型的索引中，当我们访问值时，我们得到整个数组。除了获取整个数组，我们还可以访问特定的值。让我们来看一个例子：

```py
>>> td_array[1,0] 8 >>> 
```

在前面的例子中，我们通过传递两个值来访问`td_array`的行和列。如输出所示，我们得到了值`8`。

我们也可以以不同的方式设置二维数组。首先，将我们的二维数组长度增加。让我们将长度设置为`10`。因此，为此，我们创建一个所有元素都是零的示例数组，然后我们将在其中放入值。让我们看一个例子：

```py
>>> td_array = np.zeros((10,10)) >>> td_array array([[0., 0., 0., 0., 0., 0., 0., 0., 0., 0.],
 [0., 0., 0., 0., 0., 0., 0., 0., 0., 0.], [0., 0., 0., 0., 0., 0., 0., 0., 0., 0.], [0., 0., 0., 0., 0., 0., 0., 0., 0., 0.], [0., 0., 0., 0., 0., 0., 0., 0., 0., 0.], [0., 0., 0., 0., 0., 0., 0., 0., 0., 0.], [0., 0., 0., 0., 0., 0., 0., 0., 0., 0.], [0., 0., 0., 0., 0., 0., 0., 0., 0., 0.], [0., 0., 0., 0., 0., 0., 0., 0., 0., 0.], [0., 0., 0., 0., 0., 0., 0., 0., 0., 0.]]) >>> for i in range(10):
 ...     td_array[i] = i ... >>> td_array array([[0., 0., 0., 0., 0., 0., 0., 0., 0., 0.],
 [1., 1., 1., 1., 1., 1., 1., 1., 1., 1.], [2., 2., 2., 2., 2., 2., 2., 2., 2., 2.], [3., 3., 3., 3., 3., 3., 3., 3., 3., 3.], [4., 4., 4., 4., 4., 4., 4., 4., 4., 4.], [5., 5., 5., 5., 5., 5., 5., 5., 5., 5.], [6., 6., 6., 6., 6., 6., 6., 6., 6., 6.], [7., 7., 7., 7., 7., 7., 7., 7., 7., 7.], [8., 8., 8., 8., 8., 8., 8., 8., 8., 8.], [9., 9., 9., 9., 9., 9., 9., 9., 9., 9.]]) >>>
```

在前面的例子中，我们创建了一个长度为`10`乘以`10`的二维数组。

现在让我们在其中进行一些花式索引，如下例所示：

```py
>>> td_array[[1,3,5,7]] array([[1., 1., 1., 1., 1., 1., 1., 1., 1., 1.],
 [3., 3., 3., 3., 3., 3., 3., 3., 3., 3.], [5., 5., 5., 5., 5., 5., 5., 5., 5., 5.], [7., 7., 7., 7., 7., 7., 7., 7., 7., 7.]]) >>> 
```

在前面的例子中，我们获取了特定的索引值。因此，在结果中，我们得到了输出。

# 通用数组函数

通用函数对`numpy`数组中的所有元素执行操作。现在，我们将看一个例子，对数组执行多个通用函数。首先，我们将对数组进行平方根处理。创建一个名为`sqrt_array.py`的脚本，并在其中写入以下内容：

```py
import numpy as np array = np.arange(16) print("The Array is : ",array) Square_root = np.sqrt(array) print("Square root of given array is : ", Square_root)
```

运行脚本，你会得到以下输出：

```py
student@ubuntu:~/work$ python3 sqrt_array.py
```

输出如下：

```py
The Array is : [ 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15] Square root of given array is : [0\. 1\. 1.41421356 1.73205081 2\. 2.23606798
 2.44948974 2.64575131 2.82842712 3\. 3.16227766 3.31662479 3.46410162 3.60555128 3.74165739 3.87298335]
```

在前面的例子中，我们使用`numpy`的`range`函数创建了一个简单的数组。然后我们对生成的数组应用了`sqrt()`函数，以获得数组的平方根。在获取数组的平方根后，我们将对数组应用另一个通用函数，即指数`exp()`函数。让我们看一个例子。创建一个名为`expo_array.py`的脚本，并在其中写入以下内容：

```py
import numpy as np array = np.arange(16) print("The Array is : ",array) exp = np.exp(array) print("exponential of given array is : ", exp)
```

运行脚本，你会得到以下输出：

```py
student@ubuntu:~/work$ python3 expo_array.py
```

输出如下：

```py
The Array is :  [ 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15] exponential of given array is :  [1.00000000e+00 2.71828183e+00 7.38905610e+00 2.00855369e+01
 5.45981500e+01 1.48413159e+02 4.03428793e+02 1.09663316e+03 2.98095799e+03 8.10308393e+03 2.20264658e+04 5.98741417e+04 1.62754791e+05 4.42413392e+05 1.20260428e+06 3.26901737e+06]
```

在前面的例子中，我们使用`numpy`的`range`函数创建了一个简单的数组。然后我们对生成的数组应用了`exp()`函数，以获得数组的指数。

# Pandas 模块

在本节中，我们将学习有关 pandas 模块的知识。pandas 模块提供了快速灵活的数据结构，专为处理结构化和时间序列数据而设计。pandas 模块用于数据分析。pandas 模块是建立在 NumPY 和 Matplotlib 等包之上的，并为我们提供了大部分分析和可视化工作的场所。要使用此模块的功能，您必须首先导入它。

首先，通过运行以下命令安装我们示例中需要的以下软件包：

```py
$ pip3 install pandas $ pip3 install matplotlib
```

在这里，我们将看一些使用 pandas 模块的例子。我们将学习两种数据结构：系列和数据框。我们还将看到如何使用 pandas 从`csv`文件中读取数据。

# 系列

pandas 系列是一维数组。它可以容纳任何数据类型。标签被称为索引。现在，我们将看一个不声明索引的系列和声明索引的系列的例子。首先，我们将看一个不声明索引的系列的例子。为此，请创建一个名为`series_without_index.py`的脚本，并在其中写入以下内容：

```py
import pandas as pd import numpy as np s_data = pd.Series([10, 20, 30, 40], name = 'numbers') print(s_data)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 series_without_index.py
```

输出如下：

```py
0 10 1 20 2 30 3 40 Name: numbers, dtype: int64
```

在上面的例子中，我们学习了不声明索引的系列。首先，我们导入了两个模块：pandas 和`numpy`。接下来，我们创建了将存储系列数据的`s_data`对象。在该系列中，我们创建了一个列表，而不是声明索引，我们提供了 name 属性，该属性将为列表提供一个名称，然后我们打印了数据。在输出中，左列是数据的索引。即使我们从未提供索引，pandas 也会隐式地给出。索引将始终从`0`开始。在列的下方是我们系列的名称和值的数据类型。

现在，我们将看一个声明索引的系列的例子。在这里，我们还将执行索引和切片操作。为此，请创建一个名为`series_with_index.py`的脚本，并在其中写入以下内容：

```py
import pandas as pd import numpy as np s_data = pd.Series([10, 20, 30, 40], index = ['a', 'b', 'c', 'd'], name = 'numbers') print(s_data) print() print("The data at index 2 is: ", s_data[2]) print("The data from range 1 to 3 are:\n", s_data[1:3])
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 series_with_index.py a    10 b    20 c    30 d    40 Name: numbers, dtype: int64 

The data at index 2 is:  30 The data from range 1 to 3 are:
 b    20 c    30 Name: numbers, dtype: int64
```

在上面的例子中，我们为数据在`index`属性中提供了索引值。在输出中，左列是我们提供的索引值。

# 数据框

在本节中，我们将学习有关 pandas 数据框的知识。数据框是具有列并且可能是不同数据类型的二维标记数据结构。数据框类似于 SQL 表或电子表格。在使用 pandas 时，它们是最常见的对象。

现在，我们将看一个例子，从`csv`文件中读取数据到 DataFrame 中。为此，您必须在系统中有一个`csv`文件。如果您的系统中没有`csv`文件，请按以下方式创建一个名为`employee.csv`的文件：

```py
Id, Name, Department, Country 101, John, Finance, US 102, Mary, HR, Australia 103, Geeta, IT, India 104, Rahul, Marketing, India 105, Tom, Sales, Russia
```

现在，我们将把这个`csv`文件读入 DataFrame 中。为此，请创建一个名为`read_csv_dataframe.py`的脚本，并在其中写入以下内容：

```py
import pandas as pd file_name = 'employee.csv' df = pd.read_csv(file_name) print(df) print() print(df.head(3)) print() print(df.tail(1))
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 read_csv_dataframe.py Output:
 Id    Name  Department     Country 0  101    John     Finance          US 1  102    Mary          HR   Australia 2  103   Geeta          IT       India 3  104   Rahul   Marketing       India 4  105     Tom       Sales      Russia 

 Id    Name  Department     Country 0  101    John     Finance          US 1  102    Mary          HR   Australia 2  103   Geeta          IT       India
Id  Name  Department  Country 4  105   Tom       Sales   Russia
```

在上面的例子中，我们首先创建了一个名为`employee.csv`的`csv`文件。我们使用 pandas 模块创建数据框。目标是将`csv`文件读入 DataFrame 中。接下来，我们创建了一个`df`对象，并将`csv`文件的内容读入其中。接下来我们打印一个 DataFrame。在这里，我们使用`head()`和`tail()`方法来获取特定数量的数据行。我们指定了`head(3)`，这意味着我们打印了前三行数据。我们还指定了`tail(1)`，这意味着我们打印了最后一行数据。

# 数据可视化

数据可视化是描述理解数据重要性并以可视化方式放置数据的努力的术语。在本节中，我们将看一下以下数据可视化技术：

+   Matplotlib

+   Plotly

# Matplotlib

Matplotlib 是 Python 中的数据可视化库，它允许我们使用几行代码生成图表、直方图、功率谱、条形图、误差图、散点图等。Matplotlib 通常使事情变得更容易，最困难的事情也变得可能。

要在您的 Python 程序中使用`matplotlib`，首先我们必须安装`matplotlib`。在您的终端中运行以下命令来安装`matplotlib`：

```py
$ pip3 install matplotlib
```

现在，您还必须安装另一个包`tkinter`，用于图形表示。使用以下命令安装它：

```py
$ sudo apt install python3-tk
```

在上面的例子中，我们使用`plt.figure()`函数在不同的画布上绘制东西。之后，我们使用`plt.plot()`函数。这个函数有不同的参数，对于绘制图表很有用。在上面的例子中，我们使用了一些参数；即`x1`，`x2`，`y1`和`y2`。这些是用于绘制的相应轴点。

现在，我们将看一些`matplotlib`的例子。让我们从一个简单的例子开始。创建一个名为`simple_plot.py`的脚本，并在其中写入以下内容：

```py
import matplotlib.pyplot as plt import numpy as np x = np.linspace(0, 5, 10) y = x**2 plt.plot(x,y) plt.title("sample plot") plt.xlabel("x axis") plt.ylabel("y axis") plt.show()
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 simple_plot.py
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/8d8b8572-e237-441f-8089-399fd0396d31.jpg)

在上面的例子中，我们导入了两个模块，`matplotlib`和`numpy`，来可视化数据以及分别创建数组*x*和*y*。之后，我们将两个数组绘制为`plt.plot(x,y)`。然后我们使用`xlabel()`，`ylabel()`和`title()`函数向图表添加标题和标签，并使用`plt.show()`函数显示这个绘图。因为我们在 Python 脚本中使用 Matplotlib，不要忘记在最后一行添加`plt.show()`来显示您的绘图。

现在我们将创建两个数组来显示绘图中的两行曲线，并且我们将对这两条曲线应用样式。在下面的例子中，我们将使用`ggplot`样式来绘制图表。`ggplot`是一个用于声明性创建图形的系统，基于图形语法。要绘制`ghraph`，我们只需提供数据，然后告诉`ggplot`如何映射变量以及使用什么图形原语，它会处理细节。在大多数情况下，我们从`ggplot()`样式开始。

现在，创建一个名为`simple_plot2.py`的脚本，并在其中写入以下内容：

```py
import matplotlib.pyplot as plt from matplotlib import style style.use('ggplot') x1 = [0,5,10]
y1 = [12,16,6] x2 = [6,9,11] y2 = [6,16,8] plt.subplot(2,1,1) plt.plot(x1, y1, linewidth=3) plt.title("sample plot") plt.xlabel("x axis") plt.ylabel("y axis") plt.subplot(2,1,2) plt.plot(x2, y2, color = 'r', linewidth=3) plt.xlabel("x2 axis") plt.ylabel("y2 axis") plt.show()
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 simple_plot2.py
```

输出如下：

现在`matplotlib`已经安装在您的系统中，我们将看一些例子。在绘图时，有两个重要的组件：图和轴。图是充当绘制所有内容的窗口的容器。它可以有各种类型的独立图。轴是您可以绘制数据和与之相关的任何标签的区域。轴由一个`x`轴和一个`y`轴组成。

在上面的例子中，首先我们导入了所需的模块，然后我们使用`ggplot`样式来绘制图表。我们创建了两组数组；即`x1`，`y1`和`x2`，`y2`。然后我们使用 subplot 函数`plt.subplot()`，因为它允许我们在同一画布中绘制不同的东西。如果您想要在不同的画布上显示这两个图，您也可以使用`plt.figure()`函数而不是`plt.subplot()`。

输出如下：

```py
import matplotlib.pyplot as plt from matplotlib import style style.use('ggplot') x1 = [0,5,10] y1 = [12,16,6] x2 = [6,9,11] y2 = [6,16,8] plt.figure(1) plt.plot(x1, y1, color = 'g', linewidth=3) plt.title("sample plot") plt.xlabel("x axis") plt.ylabel("y axis") plt.savefig('my_sample_plot1.jpg') plt.figure(2) plt.plot(x2, y2, color = 'r', linewidth=3) plt.xlabel("x2 axis") plt.ylabel("y2 axis") plt.savefig('my_sample_plot2.jpg') plt.show()
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 simple_plot3.py
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/a92750b5-5c24-45f9-a017-f463bba4d645.jpg)![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/8b8221ae-82a7-4746-a89c-5364f14e95d2.jpg)

现在，我们将看一下如何使用`plt.figure()`函数绘制数组并使用 Matplotlib 保存生成的图。您可以使用`savefig()`方法将它们保存为不同的格式，如`png`，`jpg`，`pdf`等。我们将把前面的图保存在一个名为`my_sample_plot.jpg`的文件中。现在，我们将看一个例子。为此，创建一个名为`simple_plot3.py`的脚本，并在其中写入以下内容：

然后，我们使用`color`参数为图形线条提供特定的颜色，并且在第三个参数中，我们使用`linewidth`，它决定了图形线条的宽度。之后，我们还使用了`savefig()`方法来以特定的图像格式保存我们的图。您可以在运行 Python 脚本的当前目录中检查它们（如果您没有指定路径）。

您可以通过直接访问该目录来打开这些图像，或者您也可以使用以下方法使用`matplotlib`来打开这些生成的图像。现在，我们将看一个打开保存的图的示例。为此，请创建一个名为`open_image.py`的脚本，并在其中写入以下内容：

```py
import matplotlib.pyplot as plt import matplotlib.image as mpimg plt.imshow(mpimg.imread('my_sample_plot1.jpg')) plt.show()
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 open_image.py
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/5f61279d-d859-4627-9969-958d6ba9cd1a.jpg)

在前面的例子中，我们使用了 Matplotlib 的`imshow()`函数来打开图的保存图像。

现在，我们将看一些不同类型的图。Matplotlib 允许我们创建不同类型的图来处理数组中的数据，如直方图、散点图、条形图等。使用不同类型的图取决于数据可视化的目的。让我们看一些这些图。

# 直方图

这种类型的图表帮助我们以一种无法仅仅使用均值或中位数来应付的方式来检查数值数据的分布。我们将使用`hist()`方法来创建一个简单的直方图。让我们看一个创建简单直方图的例子。为此，请创建一个名为`histogram_example.py`的脚本，并在其中写入以下内容：

```py
import matplotlib.pyplot as plt import numpy as np x = np.random.randn(500) plt.hist(x) plt.show()
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 histogram_example.py
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/eb702ea3-c0ab-469d-8aa9-07e1dd69fd78.jpg)

在前面的例子中，我们使用`numpy`创建了一组随机数。然后，我们使用`plt.hist()`方法绘制了这些数值数据。

# 散点图

这种类型的图表将数据显示为一组点。它提供了一种方便的方式来可视化数值值的关系。它还帮助我们理解多个变量之间的关系。我们将使用`scatter()`方法来绘制散点图中的数据。在散点图中，点的位置取决于其`x`和`y`轴的值；也就是说，数据集中的每个值都是水平或垂直维度中的一个位置。让我们看一个散点图的例子。创建一个名为`scatterplot_example.py`的脚本，并在其中写入以下内容：

```py
import matplotlib.pyplot as plt import numpy as np x = np.linspace(-2,2,100) y = np.random.randn(100) colors = np.random.rand(100) plt.scatter(x,y,c=colors) plt.show()
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 scatterplot_example.py
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/985d2b20-6987-46b5-a513-fcd962fd61de.jpg)

在前面的例子中，我们得到了`x`和`y`的值。然后，我们使用`plt.scatter()`方法来绘制这些值，以获得`x`和`y`值的散点图。

# 条形图

条形图是用矩形条表示数据的图表。您可以将它们垂直或水平绘制。创建一个名为`bar_chart.py`的脚本，并在其中写入以下内容：

```py
import matplotlib.pyplot as plt from matplotlib import style style.use('ggplot') x1 = [4,8,12] y1 = [12,16,6] x2 = [5,9,11] y2 = [6,16,8] plt.bar(x1,y1,color = 'g',linewidth=3) plt.bar(x2,y2,color = 'r',linewidth=3) plt.title("Bar plot") plt.xlabel("x axis") plt.ylabel("y axis") plt.show()
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 bar_chart.py
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/692d75ea-6b6f-4e8b-8290-2f3c9c654f2b.jpg)

在前面的例子中，我们有两组值：`x1`，`y1`和`x2`，`y2`。在获得数值数据后，我们使用`plt.bar()`方法来绘制当前数据的条形图。

有多种技术可用于绘制数据。其中，有几种使用`matplotlib`进行数据可视化的技术或方法，我们已经看到了。我们还可以使用另一种数据可视化工具`plotly`来执行这些操作。

# Plotly

Plotly 是 Python 中的一个交互式、开源的绘图库。它是一个图表库，提供了 30 多种图表类型，如科学图表、3D 图形、统计图表、金融图表等。

要在 Python 中使用`plotly`，首先我们必须在系统中安装它。要安装`plotly`，请在您的终端中运行以下命令：

```py
$ pip3 install plotly
```

我们可以在线和离线使用`plotly`。对于在线使用，你需要有一个`plotly`账户，之后你需要在 Python 中设置你的凭据：

```py
 plotly.tools.set_credentials_file(username='Username', api_key='APIkey')
```

要离线使用`plotly`，我们需要使用`plotly`函数：`plotly.offline.plot()`

在这一部分，我们将使用 plotly 离线。现在，我们将看一个简单的例子。为此，创建一个名为`sample_plotly.py`的脚本，并在其中写入以下内容：

```py
import plotly from plotly.graph_objs import Scatter, Layout plotly.offline.plot({
 "data": [Scatter(x=[1, 4, 3, 4], y=[4, 3, 2, 1])], "layout": Layout(title="plotly_sample_plot") })
```

将前面的脚本命名为`sample_plotly.py`运行。你将得到以下输出：

```py
student@ubuntu:~/work$ python3 sample_plotly.py
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/d639864a-5006-48d1-bbc5-9772566cc3b5.jpg)

在前面的例子中，我们导入了`plotly`模块，然后将`plotly`设置为离线使用。我们在其中放入了一些有用于绘制图表的参数。在例子中，我们使用了一些参数：`data`和`layout`。在`data`参数中，我们使用散点函数定义了`x`和`y`数组，这些数组具有要在`x`和`y`轴上绘制的值。然后我们使用`layout`参数，在其中我们定义了布局函数以为图表提供标题。前面程序的输出保存为 HTML 文件，并在默认浏览器中打开。这个 HTML 文件与你的脚本在同一个目录中。

现在让我们看一些不同类型的图表来可视化数据。所以，首先，我们将从散点图开始。

# 散点图

创建一个名为`scatter_plot_plotly.py`的脚本，并在其中写入以下内容：

```py
import plotly import plotly.graph_objs as go import numpy as np  x_axis = np.random.randn(100) y_axis = np.random.randn(100)  trace = go.Scatter(x=x_axis, y=y_axis, mode = 'markers') data_set = [trace] plotly.offline.plot(data_set, filename='scatter_plot.html')
```

运行脚本，你将得到以下输出：

```py
student@ubuntu:~/work$ python3 scatter_plot_plotly.py
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/728d2983-9f6e-4a22-8a99-1ce9a9e585bd.jpg)

在前面的例子中，我们导入了`plotly`，然后通过使用`numpy`创建了随机数据，并在脚本中导入了`numpy`模块。生成数据集后，我们创建了一个名为`trace`的对象，并将我们的数值数据插入其中以进行散点。最后，我们将`trace`对象中的数据放入`plotly.offline.plot()`函数中，以获得数据的散点图。与我们的第一个示例图一样，这个例子的输出也以 HTML 格式保存，并显示在默认的网络浏览器中。

# 线散点图

我们还可以创建一些更有信息量的图表，比如线散点图。让我们看一个例子。创建一个名为`line_scatter_plot.py`的脚本，并在其中写入以下内容：

```py
import plotly import plotly.graph_objs as go import numpy as np x_axis = np.linspace(0, 1, 50) y0_axis = np.random.randn(50)+5 y1_axis = np.random.randn(50) y2_axis = np.random.randn(50)-5 trace0 = go.Scatter(x = x_axis,y = y0_axis,mode = 'markers',name = 'markers') trace1 = go.Scatter(x = x_axis,y = y1_axis,mode = 'lines+markers',name = 'lines+markers') trace2 = go.Scatter(x = x_axis,y = y2_axis,mode = 'lines',name = 'lines') data_sets = [trace0, trace1, trace2] plotly.offline.plot(data_sets, filename='line_scatter_plot.html')
```

运行脚本，你将得到以下输出：

```py
student@ubuntu:~/work$ python3 line_scatter_plot.py
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/61d2fa81-8592-4c5a-95ad-d68670ca8126.jpg)

在前面的例子中，我们导入了`plotly`，以及`numpy`模块。然后我们为 x 轴生成了一些随机值，也为三个不同的 y 轴生成了随机值。之后，我们将这些数据放入创建的`trace`对象中，最后将该数据集放入 plotly 的离线函数中。然后我们得到了散点和线的格式的输出。这个例子的输出文件以`line_scatter_plot.html`的名称保存在你当前的目录中。

# 箱线图

箱线图通常是有信息量的，也很有帮助，特别是当你有太多要展示但数据很少的时候。让我们看一个例子。创建一个名为`plotly_box_plot.py`的脚本，并在其中写入以下内容：

```py
import random import plotly from numpy import * N = 50. c = ['hsl('+str(h)+',50%'+',50%)' for h in linspace(0, 360, N)] data_set = [{
 'y': 3.5*sin(pi * i/N) + i/N+(1.5+0.5*cos(pi*i/N))*random.rand(20), 'type':'box', 'marker':{'color': c[i]} } for i in range(int(N))] layout = {'xaxis': {'showgrid':False,'zeroline':False, 'tickangle':45,'showticklabels':False},
 'yaxis': {'zeroline':False,'gridcolor':'white'}, 'paper_bgcolor': 'rgb(233,233,233)', 'plot_bgcolor': 'rgb(233,233,233)', } plotly.offline.plot(data_set)
```

运行脚本，你将得到以下输出：

```py
student@ubuntu:~/work$ python3 plotly_box_plot.py
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/976d4c5a-f03e-4eb3-93d3-39456e5e1a92.jpg)

在前面的例子中，我们导入了`plotly`，以及`numpy`模块。然后我们声明 N 为箱线图中的总箱数，并通过固定颜色的饱和度和亮度以及围绕色调进行变化，生成了一个彩虹颜色的数组。每个箱子由一个包含数据、类型和颜色的字典表示。我们使用列表推导来描述 N 个不同颜色的箱子，每个箱子都有不同的随机生成的数据。之后，我们格式化输出的布局并通过离线的`plotly`函数绘制数据。

# 等高线图

轮廓图通常用作科学图，并在显示热图数据时经常使用。让我们看一个轮廓图的例子。创建一个名为`contour_plotly.py`的脚本，并在其中写入以下内容：

```py
from plotly import tools import plotly import plotly.graph_objs as go trace0 = go.Contour(
 z=[[1, 2, 3, 4, 5, 6, 7, 8], [2, 4, 7, 12, 13, 14, 15, 16], [3, 1, 6, 11, 12, 13, 16, 17], [4, 2, 7, 7, 11, 14, 17, 18], [5, 3, 8, 8, 13, 15, 18, 19], [7, 4, 10, 9, 16, 18, 20, 19], [9, 10, 5, 27, 23, 21, 21, 21]], line=dict(smoothing=0), ) trace1 = go.Contour(
 z=[[1, 2, 3, 4, 5, 6, 7, 8], [2, 4, 7, 12, 13, 14, 15, 16], [3, 1, 6, 11, 12, 13, 16, 17], [4, 2, 7, 7, 11, 14, 17, 18], [5, 3, 8, 8, 13, 15, 18, 19], [7, 4, 10, 9, 16, 18, 20, 19], [9, 10, 5, 27, 23, 21, 21, 21]], line=dict(smoothing=0.95), ) data = tools.make_subplots(rows=1, cols=2,
 subplot_titles=('Smoothing_not_applied', 'smoothing_applied')) data.append_trace(trace0, 1, 1) data.append_trace(trace1, 1, 2) plotly.offline.plot(data)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 contour_plotly.py This is the format of your plot grid: [ (1,1) x1,y1 ]  [ (1,2) x2,y2 ]
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/5ddc9f4d-947e-426e-ad4a-a6fa45c5a213.jpg)

在前面的例子中，我们取了一个数据集，并对其应用了`contour()`函数。然后我们将轮廓数据附加到`data_set`中，并最终对数据应用了`plotly`函数以获得输出。这些是 plotly 中用于以可视方式绘制数据的一些技术。

# 总结

在本章中，我们学习了 NumPY 和 Pandas 模块，以及数据可视化技术。在 NumPY 模块部分，我们学习了数组的索引和切片以及通用数组函数。在 pandas 模块部分，我们学习了 Series 和 DataFrames。我们还学习了如何将`csv`文件读入 DataFrame。在数据可视化中，我们学习了 Python 中用于数据可视化的库：`matplotlib`和`plotly`。

在下一章中，您将学习有关 MySQL 和 SQLite 数据库管理的知识。

# 问题

1.  什么是 NumPy 数组？

1.  以下代码片段的输出是什么？

```py
import numpy as np
# input array
in_arr1 = np.array([[ 1, 2, 3], [ -1, -2, -3]] )
print ("1st Input array : \n", in_arr1) 
in_arr2 = np.array([[ 4, 5, 6], [ -4, -5, -6]] )
print ("2nd Input array : \n", in_arr2) 
# Stacking the two arrays horizontally
out_arr = np.hstack((in_arr1, in_arr2))
print ("Output stacked array :\n ", out_arr)
```

1.  如何比`np.sum`更快地对小数组求和？

1.  如何从 Pandas DataFrame 中删除索引、行或列？

1.  如何将 Pandas DataFrame 写入文件？

1.  pandas 中的 NaN 是什么？

1.  如何从 pandas DataFrame 中删除重复项？

1.  如何更改使用 Matplotlib 绘制的图形的大小？

1.  Python 中绘制图形的可用替代方法是什么？

# 进一步阅读

+   10 分钟到 pandas 文档：[`pandas.pydata.org/pandas-docs/stable/`](https://pandas.pydata.org/pandas-docs/stable/)

+   NumPy 教程：[`docs.scipy.org/doc/numpy/user/quickstart.html`](https://docs.scipy.org/doc/numpy/user/quickstart.html)

+   使用 plotly 进行图形绘制：[`plot.ly/d3-js-for-python-and-pandas-charts/`](https://plot.ly/d3-js-for-python-and-pandas-charts/)


# 第十八章：MySQL 和 SQLite 数据库管理

在本章中，您将学习有关 MySQL 和 SQLite 数据库管理的知识。您将学习如何安装 MySQL 和 SQLite。您还将学习如何创建用户，授予权限，创建数据库，创建表，将数据插入表中，并查看表中的所有记录，特定记录，并更新和删除数据。

在本章中，您将学习以下内容：

+   MySQL 数据库管理

+   SQLite 数据库管理

# MySQL 数据库管理

本节将介绍使用 Python 进行 MySQL 数据库管理。您已经知道 Python 有各种模块用于`mysql`数据库管理。因此，我们将在这里学习有关 MySQLdb 模块的知识。`mysqldb`模块是 MySQL 数据库服务器的接口，用于提供 Python 数据库 API。

让我们学习如何安装 MySQL 和 Python 的`mysqldb`包。为此，请在终端中运行以下命令：

```py
$ sudo apt install mysql-server
```

此命令安装 MySQL 服务器和各种其他软件包。在安装软件包时，我们被提示为 MySQL root 帐户输入密码：

+   以下代码用于检查是否安装了`mysqldb`包：

```py
$ apt-cache search MySQLdb
```

+   以下是用于安装 MySQL 的 Python 接口：

```py
$ sudo apt-get install python3-mysqldb
```

+   现在，我们将检查`mysql`是否安装正确。为此，在终端中运行以下命令：

```py
student@ubuntu:~$ sudo mysql -u root -p 
```

一旦命令运行，您将获得以下输出：

```py
Enter password: Welcome to the MySQL monitor.  Commands end with ; or \g. Your MySQL connection id is 10 Server version: 5.7.24-0ubuntu0.18.04.1 (Ubuntu)
Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.
Oracle is a registered trademark of Oracle Corporation and/or its affiliates. Other names may be trademarks of their respective owners. Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
mysql>
```

通过运行`sudo mysql -u root -p`，您将获得`mysql`控制台。有一些命令用于列出数据库和表，并使用数据库来存储我们的工作。我们将逐一看到它们：

+   这是用于列出所有数据库的：

```py
show databases;
```

+   这是用于使用数据库的：

```py
use database_name;
```

每当我们退出 MySQL 控制台并在一段时间后再次登录时，我们必须使用`use database_name;`语句。使用此命令的目的是我们的工作将保存在我们的数据库中。我们可以通过以下示例详细了解这一点：

+   以下代码用于列出所有表：

```py
show tables;
```

这些是我们用于列出数据库，使用数据库和列出表的命令。

现在，我们将使用`mysql`控制台中的 create database 语句创建数据库。现在，使用`mysql -u root -p`打开`mysql`控制台，然后输入您在安装时输入的密码，然后按*Enter*。接下来，创建您的数据库。在本节中，我们将创建一个名为`test`的数据库，并在本节中将使用该数据库：

```py
student@ubuntu:~/work/mysql_testing$ sudo mysql -u root -p  Output: Enter password: Welcome to the MySQL monitor.  Commands end with ; or \g. Your MySQL connection id is 16 Server version: 5.7.24-0ubuntu0.18.04.1 (Ubuntu)
Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.
Oracle is a registered trademark of Oracle Corporation and/or its affiliates. Other names may be trademarks of their respective owners. Type 'help;' or '\h' for help. Type '\c' to clear the current input statement. mysql> mysql> show databases; +--------------------+ | Database           | +--------------------+ | information_schema | | mysql              | | performance_schema | | sys                | +--------------------+ 4 rows in set (0.10 sec)
mysql> create database test; Query OK, 1 row affected (0.00 sec)
mysql> show databases; +--------------------+ | Database           | +--------------------+ | information_schema | | mysql              | | performance_schema | | sys                | | test               | +--------------------+ 5 rows in set (0.00 sec)
mysql> use test; Database changed mysql>
```

首先，我们使用 show databases 列出了所有数据库。接下来，我们使用 create `database`语句创建了我们的数据库 test。然后，我们再次执行 show databases 以查找我们的数据库是否已创建。我们的数据库现在已创建。接下来，我们使用该数据库来存储我们正在进行的工作。

现在，我们将创建一个用户并授予该用户权限。运行以下命令：

```py
mysql> create user 'test_user'@'localhost' identified by 'test123'; Query OK, 0 rows affected (0.06 sec) mysql> grant all on test.* to 'test_user'@'localhost'; Query OK, 0 rows affected (0.02 sec)
mysql>
```

我们创建了一个名为`test_user`的用户；该用户的密码为`test123`。接下来，我们授予我们的`test_user`用户所有权限。现在，通过运行`quit;`或`exit;`命令退出`mysql`控制台。

现在，我们将看一些示例，获取数据库版本，创建表，将一些数据插入表中，更新数据和删除数据。

# 获取数据库版本

首先，我们将看一个获取数据库版本的示例。为此，我们将创建一个`get_database_version.py`脚本，并在其中编写以下内容：

```py
import MySQLdb as mdb import sys  con_obj = mdb.connect('localhost', 'test_user', 'test123', 'test') cur_obj = con_obj.cursor() cur_obj.execute("SELECT VERSION()") version = cur_obj.fetchone() print ("Database version: %s " % version) con_obj.close()
```

在运行此脚本之前，非常重要遵循先前的步骤；不应跳过它们。

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work/mysql_testing$ python3 get_database_version.py Output: Database version: 5.7.24-0ubuntu0.18.04.1
```

在上面的示例中，我们得到了数据库版本。首先，我们导入了 MySQLdb 模块。然后我们编写了连接字符串。在连接字符串中，我们提到了我们的用户名、密码和数据库名称。接下来，我们创建了一个游标对象，用于执行 SQL 查询。在`execute()`中，我们传递了一个 SQL 查询。`fetchone()`检索查询结果的下一行。接下来，我们打印了结果。`close()`方法关闭了数据库连接。

# 创建表和插入数据

现在，我们将创建一个表，并向其中插入一些数据。为此，创建一个`create_insert_data.py`脚本，并在其中写入以下内容：

```py
import MySQLdb as mdb con_obj = mdb.connect('localhost', 'test_user', 'test123', 'test') with con_obj:
 cur_obj = con_obj.cursor() cur_obj.execute("DROP TABLE IF EXISTS books") cur_obj.execute("CREATE TABLE books(Id INT PRIMARY KEY AUTO_INCREMENT, Name VARCHAR(100))") cur_obj.execute("INSERT INTO books(Name) VALUES('Harry Potter')") cur_obj.execute("INSERT INTO books(Name) VALUES('Lord of the rings')") cur_obj.execute("INSERT INTO books(Name) VALUES('Murder on the Orient Express')") cur_obj.execute("INSERT INTO books(Name) VALUES('The adventures of Sherlock Holmes')") cur_obj.execute("INSERT INTO books(Name) VALUES('Death on the Nile')") print("Table Created !!") print("Data inserted Successfully !!")
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work/mysql_testing$ python3 create_insert_data.py Output: Table Created !! Data inserted Successfully !!
```

要检查您的表是否成功创建，请打开您的`mysql`控制台并运行以下命令：

```py
student@ubuntu:~/work/mysql_testing$ sudo mysql -u root -p Enter password: Welcome to the MySQL monitor.  Commands end with ; or \g. Your MySQL connection id is 6 Server version: 5.7.24-0ubuntu0.18.04.1 (Ubuntu)
Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.
Oracle is a registered trademark of Oracle Corporation and/or its affiliates. Other names may be trademarks of their respective owners.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement. mysql> mysql> mysql> use test; Reading table information for completion of table and column names You can turn off this feature to get a quicker startup with -A Database changed mysql> show tables; +----------------+ | Tables_in_test | +----------------+ | books          | +----------------+ 1 row in set (0.00 sec)
```

您可以看到您的 books 表已创建。

# 检索数据

要从表中检索数据，我们使用`select`语句。现在，我们将从我们的 books 表中检索数据。为此，创建一个`retrieve_data.py`脚本，并在其中写入以下内容：

```py
import MySQLdb as mdb con_obj = mdb.connect('localhost', 'test_user', 'test123', 'test') with con_obj:
 cur_obj = con_obj.cursor() cur_obj.execute("SELECT * FROM books") records = cur_obj.fetchall() for r in records: print(r)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work/mysql_testing$ python3 retrieve_data.py Output: (1, 'Harry Potter') (2, 'Lord of the rings') (3, 'Murder on the Orient Express') (4, 'The adventures of Sherlock Holmes') (5, 'Death on the Nile')
```

在上面的示例中，我们从表中检索了数据。我们使用了 MySQLdb 模块。我们编写了一个连接字符串并创建了一个游标对象来执行 SQL 查询。在`execute()`中，我们编写了一个 SQL`select`语句。最后，我们打印了记录。

# 更新数据

现在，如果我们想对记录进行一些更改，我们可以使用 SQL`update`语句。我们将看一个`update`语句的示例。为此，创建一个`update_data.py`脚本，并在其中写入以下内容：

```py
import MySQLdb as mdb con_obj = mdb.connect('localhost', 'test_user', 'test123', 'test') cur_obj = con_obj.cursor() cur_obj.execute("UPDATE books SET Name = 'Fantastic Beasts' WHERE Id = 1")try:
 con_obj.commit() except:
 con_obj.rollback()
```

按以下方式运行脚本：

```py
student@ubuntu:~/work/mysql_testing$ python3 update_data.py
```

现在，要检查您的记录是否已更新，请按以下方式运行`retrieve_data.py`：

```py
student@ubuntu:~/work/mysql_testing$ python3 retrieve_data.py Output: (1, 'Fantastic Beasts') (2, 'Lord of the rings') (3, 'Murder on the Orient Express') (4, 'The adventures of Sherlock Holmes') (5, 'Death on the Nile')
```

您可以看到 ID 为`1`的数据已更新。在上面的示例中，在`execute()`中，我们编写了一个`update`语句，将更新 ID 为`1`的数据。

# 删除数据

要从表中删除特定记录，请使用`delete`语句。我们将看一个删除数据的示例。创建一个`delete_data.py`脚本，并在其中写入以下内容：

```py
import MySQLdb as mdb con_obj = mdb.connect('localhost', 'test_user', 'test123', 'test') cur_obj = con_obj.cursor() cur_obj.execute("DELETE FROM books WHERE Id = 5"); try:
 con_obj.commit() except:
 con_obj.rollback() 
```

按以下方式运行脚本：

```py
student@ubuntu:~/work/mysql_testing$ python3 delete_data.py
```

现在，要检查您的记录是否已删除，请按以下方式运行`retrieve_data.py`脚本：

```py
student@ubuntu:~/work/mysql_testing$ python3 retrieve_data.py Output: (1, 'Fantastic Beasts') (2, 'Lord of the rings') (3, 'Murder on the Orient Express') (4, 'The adventures of Sherlock Holmes')
```

您可以看到，您的 ID 为`5`的记录已被删除。在上面的示例中，我们使用了`delete`语句来删除特定记录。在这里，我们删除了 ID 为`5`的记录。您还可以根据自己选择的任何字段名删除记录。

# SQLite 数据库管理

在本节中，我们将学习如何安装和使用 SQLite。Python 有`sqlite3`模块来执行 SQLite 数据库任务。SQLite 是一个无服务器、零配置、事务性 SQL 数据库引擎。SQLite 非常快速和轻量级。整个数据库存储在单个磁盘文件中。

现在，我们将首先安装 SQLite。在终端中运行以下命令：

```py
$ sudo apt install sqlite3
```

在本节中，我们将学习以下操作：创建数据库、创建表、向表中插入数据、检索数据，以及从表中更新和删除数据。我们将逐个查看每个操作。

现在，首先，我们将看如何在 SQLite 中创建数据库。要创建数据库，您只需在终端中输入以下命令：

```py
$ sqlite3 test.db
```

运行此命令后，您将在终端中打开`sqlite`控制台，如下所示：

```py
student@ubuntu:~$ sqlite3 test.db SQLite version 3.22.0 2018-01-22 18:45:57 Enter ".help" for usage hints. sqlite>
```

您的数据库已通过简单运行`sqlite3 test.db`创建。

# 连接到数据库

现在，我们将看到如何连接到数据库。为此，我们将创建一个脚本。Python 已经在标准库中包含了一个`sqlite3`模块。我们只需要在使用 SQLite 时导入它。创建一个`connect_database.py`脚本，并在其中写入以下内容：

```py
import sqlite3 con_obj = sqlite3.connect('test.db') print ("Database connected successfully !!")
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work $ python3 connect_database.py Output: Database connected successfully !!
```

在前面的例子中，我们导入了`sqlite3`模块来执行功能。现在，检查您的目录，您将在目录中找到创建的`test.db`文件。

# 创建表

现在，我们将在我们的数据库中创建一个表。为此，我们将创建一个`create_table.py`脚本，并在其中写入以下内容：

```py
import sqlite3 con_obj = sqlite3.connect("test.db") with con_obj:
 cur_obj = con_obj.cursor() cur_obj.execute("""CREATE TABLE books(title text, author text)""")  print ("Table created")
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work $ python3 create_table.py Output: Table created
```

在前面的例子中，我们使用`CREATE TABLE`语句创建了一个名为 books 的表。首先，我们使用`test.db`建立了与数据库的连接。接下来，我们创建了一个游标对象，用于在数据库上执行 SQL 查询。

# 插入数据

现在，我们将向我们的表中插入数据。为此，我们将创建一个`insert_data.py`脚本，并在其中写入以下内容：

```py
import sqlite3 con_obj = sqlite3.connect("test.db") with con_obj:
 cur_obj = con_obj.cursor() cur_obj.execute("INSERT INTO books VALUES ('Pride and Prejudice', 'Jane Austen')") cur_obj.execute("INSERT INTO books VALUES ('Harry Potter', 'J.K Rowling')") cur_obj.execute("INSERT INTO books VALUES ('The Lord of the Rings', 'J. R. R. Tolkien')") cur_obj.execute("INSERT INTO books VALUES ('Murder on the Orient Express', 'Agatha Christie')") cur_obj.execute("INSERT INTO books VALUES ('A Study in Scarlet', 'Arthur Conan Doyle')") con_obj.commit() print("Data inserted Successfully !!")
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 insert_data.py Output: Data inserted Successfully !!
```

在前面的例子中，我们向我们的表中插入了一些数据。为此，我们在 SQL 语句中使用了`insert`。通过使用`commit()`，我们告诉数据库保存所有当前的事务。

# 检索数据

现在，我们将从表中检索数据。为此，创建一个`retrieve_data.py`脚本，并在其中写入以下内容：

```py
import sqlite3 con_obj = sqlite3.connect('test.db') cur_obj = con_obj.execute("SELECT title, author from books")
for row in cur_obj:
 print ("Title = ", row[0]) print ("Author = ", row[1], "\n") con_obj.close()
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 retrieve_data.py Output: Title =  Pride and Prejudice Author =  Jane Austen
Title =  Harry Potter Author =  J.K Rowling
Title =  The Lord of the Rings Author =  J. R. R. Tolkien
Title =  Murder on the Orient Express Author =  Agatha Christie
Title =  A Study in Scarlet Author =  Arthur Conan Doyle
```

在前面的例子中，我们导入了`sqlite3`模块。接下来，我们连接到了我们的`test.db`数据库。为了检索数据，我们使用了`select`语句。最后，我们打印了检索到的数据。

您还可以在`sqlite3`控制台中检索数据。为此，首先启动 SQLite 控制台，然后按照以下方式检索数据：

```py
student@ubuntu:~/work/sqlite3_testing$ sqlite3 test.db Output: SQLite version 3.22.0 2018-01-22 18:45:57 Enter ".help" for usage hints. sqlite> sqlite> select * from books; Pride and Prejudice|Jane Austen Harry Potter|J.K Rowling The Lord of the Rings|J. R. R. Tolkien Murder on the Orient Express|Agatha Christie A Study in Scarlet|Arthur Conan Doyle sqlite>
```

# 更新数据

我们可以使用`update`语句从我们的表中更新数据。现在，我们将看一个更新数据的例子。为此，创建一个`update_data.py`脚本，并在其中写入以下内容：

```py
import sqlite3 con_obj = sqlite3.connect("test.db") with con_obj:
            cur_obj = con_obj.cursor()
 sql = """ UPDATE books SET author = 'John Smith' WHERE author = 'J.K Rowling' """ cur_obj.execute(sql) print("Data updated Successfully !!")
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work $ python3 update_data.py Output: Data updated Successfully !!
```

现在，要检查数据是否实际上已更新，请运行`retrieve_data.py`，或者您可以转到 SQLite 控制台并运行`select * from books;`。您将得到更新后的输出如下：

```py
By running retrieve_data.py: Output: student@ubuntu:~/work$ python3 retrieve_data.py Title =  Pride and Prejudice Author =  Jane Austen
Title =  Harry Potter Author =  John Smith
Title =  The Lord of the Rings Author =  J. R. R. Tolkien
Title =  Murder on the Orient Express Author =  Agatha Christie
Title =  A Study in Scarlet Author =  Arthur Conan Doyle
Checking on SQLite console: Output: student@ubuntu:~/work$ sqlite3 test.db SQLite version 3.22.0 2018-01-22 18:45:57 Enter ".help" for usage hints. sqlite> sqlite> select * from books; Pride and Prejudice|Jane Austen Harry Potter|John Smith The Lord of the Rings|J. R. R. Tolkien Murder on the Orient Express|Agatha Christie A Study in Scarlet|Arthur Conan Doyle sqlite>
```

# 删除数据

现在，我们将看一个从表中删除数据的例子。我们将使用`delete`语句来做到这一点。创建一个`delete_data.py`脚本，并在其中写入以下内容：

```py
import sqlite3 con_obj = sqlite3.connect("test.db") with con_obj:
 cur_obj = con_obj.cursor()            sql = """
 DELETE FROM books WHERE author = 'John Smith' """ cur_obj.execute(sql) print("Data deleted successfully !!")
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work $ python3 delete_data.py Output: Data deleted successfully !!
```

在前面的例子中，我们从表中删除了一条记录。我们使用了`delete` SQL 语句。现在，要检查数据是否成功删除，请运行`retrieve_data.py`或启动 SQLite 控制台，如下所示：

```py
By running retrieve_data.py Output: student@ubuntu:~/work$ python3 retrieve_data.py Title =  Pride and Prejudice Author =  Jane Austen
Title =  The Lord of the Rings Author =  J. R. R. Tolkien
Title =  Murder on the Orient Express Author =  Agatha Christie
Title =  A Study in Scarlet Author =  Arthur Conan Doyle
```

您可以看到作者是`john smith`的记录已被删除：

```py
Checking on SQLite console: Output: student@ubuntu:~/work$ sqlite3 test.db SQLite version 3.22.0 2018-01-22 18:45:57 Enter ".help" for usage hints. sqlite> sqlite> select * from books; Pride and Prejudice|Jane Austen The Lord of the Rings|J. R. R. Tolkien Murder on the Orient Express|Agatha Christie A Study in Scarlet|Arthur Conan Doyle sqlite>
```

# 总结

在本章中，我们学习了 MySQL 以及 SQLite 数据库管理。我们创建了数据库和表。然后我们在表中插入了一些记录。使用`select`语句，我们检索了记录。我们还学习了更新和删除数据。

# 问题

1.  数据库用于什么？

1.  数据库中的 CRUD 是什么？

1.  我们可以连接远程数据库吗？如果可以，请举例说明。

1.  我们可以在 Python 代码中编写触发器和存储过程吗？

1.  什么是 DML 和 DDL 语句？

# 进一步阅读

+   使用 PyMySQL 库：[`zetcode.com/python/pymysql/`](http://zetcode.com/python/pymysql/)

+   MySQLdb，Python 连接指南：[`mysqlclient.readthedocs.io/`](https://mysqlclient.readthedocs.io/)

+   SQLite 数据库的 DB-API 2.0 接口：[`docs.python.org/3/library/sqlite3.html`](https://docs.python.org/3/library/sqlite3.html)


# 第十九章：评估

# 第一章，Python 脚本概述

1.  迭代器是可以被迭代的对象。它是一个会返回数据的对象，每次返回一个元素。生成器是一个可以迭代的函数，它返回一个对象。

1.  列表是可变的。

1.  Python 中的数据结构是可以一起保存一些数据的结构。换句话说，它们用于存储相关数据的集合。

1.  我们可以通过使用索引值来访问列表中的值。

1.  模块只是包含 Python 语句和定义的文件。

# 第二章，调试和分析 Python 脚本

1.  要调试程序，使用`pdb`模块。

1.  a) 在运行`ipython3`之前，使用`sudo apt-get install ipython3`进行安装。

b) `%lsmagic`。

1.  全局解释器锁是计算机语言解释器中使用的一种机制，用于同步线程的执行，以便一次只有一个本机线程可以执行

1.  以下是答案：

a) `PYTHONPATH`：它的作用类似于 PATH。此变量告诉 Python 解释器在程序中导入的模块文件的位置。它应该包括 Python 源库目录和包含 Python 源代码的目录。`PYTHONPATH`有时会被 Python 安装程序预设。

b) `PYTHONSTARTUP`：它包含包含 Python 源代码的初始化文件的路径。每次启动解释器时都会执行它。在 Unix 中，它被命名为`.pythonrc.py`，它包含加载实用程序或修改`PYTHONPATH`的命令。

c) `PYTHONCASEOK`：在 Windows 中用于指示 Python 在导入语句中找到第一个不区分大小写的匹配项。将此变量设置为任何值以激活它。

d) `PYTHONHOME`：这是一个替代的模块搜索路径。通常嵌入在`PYTHONSTARTUP`或`PYTHONPATH`目录中，以便轻松切换模块库。

1.  答案：`[0]`。

在函数中创建了一个新的列表对象，并且引用丢失了。可以通过比较`k`在`k = [1]`之前和之后的 ID 来检查这一点。

1.  答案：b. 变量名不应以数字开头。

# 第三章，单元测试 - 单元测试框架简介

1.  单元测试是软件测试的一种级别，其中测试软件的各个单元/组件。目的是验证软件的每个单元是否按设计执行。

自动化测试是一种自动化技术，其中测试人员自己编写脚本并使用适当的软件来测试软件。基本上是手动流程的自动化过程。

手动测试是发现软件程序中的缺陷或错误的过程。在这种方法中，测试人员扮演端用户的重要角色，并验证应用程序的所有功能是否正常工作。

1.  Unittest，mock，nose，`pytest`。

1.  测试用例是为验证软件应用程序的特定功能或功能而执行的一组操作。本教程描述了测试用例的设计以及其各个组件的重要性。

1.  PEP 8 是 Python 的风格指南。这是一组规则，用于格式化您的 Python 代码，以最大限度地提高其可读性。按照规范编写代码有助于使具有许多编写者的大型代码库更加统一和可预测。

# 第四章，自动化常规管理活动

1.  `readline()`方法从文件中读取整行。字符串中保留了尾随的换行符。如果存在大小参数并且为非负，则它是包括尾随换行符在内的最大字节计数，并且可能返回不完整的行。

1.  读取：`cat`。

创建新文件：`touch`。

删除文件：`rm`。

列出当前目录中的文件：`ls`。

1.  以下是答案：

```py
os.system(“shell_command”)
subprocess.getstatusoutput(“shell_command”)
```

1.  以下是答案：

```py
import configparser as config
config.set(section, option, value)
```

1.  以下是答案：

```py
 psutil, fabric, salt, asnible, buildbot, shinken
```

1.  以下是答案：

```py
input() 
sys.stdin.readline()
```

1.  当您想要改变列表时使用`list.sort()`，当您想要一个新的排序对象时使用`sorted()`。对于尚未是列表的可迭代对象，使用`sorted()`进行排序更快。对于列表，`list.sort()`比`sorted()`更快，因为它不必创建副本。

# 第五章，处理文件、目录和数据

1.  通过使用`pathlib`库。

1.  以下是答案：

```py
print(*objects, sep=' ', end='\n', file=sys.stdout, flush=False)
```

1.  如果没有参数调用，则返回当前范围内的名称。否则，返回给定对象的属性（部分）组成的名称的按字母顺序排列的列表，以及可从该对象到达的属性。

1.  DataFrame 是一个二维大小、可变且可能异构的带标签轴的表格数据结构。

Series 是 DataFrame 的单列数据结构，不仅在概念上是如此，而且在内存中实际上是作为一系列存储的。

1.  列表推导提供了一种简洁的方法来创建新列表。

1.  是的：

```py
Set comprehension {s**2 for s in range(10)}
Dict comprehension {n: n**2 for n in range(5)}
```

1.  以下是答案：

```py
df.head(number of lines) default blank 
df.tail(number of lines) default blank
```

1.  以下是答案：

```py
[i for i in range(10) if i%2]
```

1.  答案：b。这是一个元素列表。

# 第六章，文件归档、加密和解密

1.  是的，使用 Python 的`pyminizip`库。

1.  上下文管理器是一种在需要时精确分配和释放某种资源的方法。最简单的例子是文件访问：

```py
with open ("foo", 'w+') as foo:
foo.write("Hello!")
is similar to
foo = open ("foo", 'w+'):
 foo.write("Hello!")
foo.close()
```

1.  在 Python 中，pickling 指的是将对象序列化为二进制流的过程，而 unpickling 是其相反过程。

1.  无参数且无返回值的函数

无参数且有返回值的函数

带参数且无返回值的函数

带参数和返回值的函数

# 第七章，文本处理和正则表达式

1.  正则表达式是编程中用于模式匹配的方法。正则表达式提供了一种灵活而简洁的方法来匹配文本字符串。

1.  以下是答案：

```py
import redef is_allowed_specific_char(string):
 charRe = re.compile(r'[^a-zA-Z0-9.]')
 string = charRe.search(string)
 return not bool(string)
 print(is_allowed_specific_char("ABCDEFabcdef123450"))
 print(is_allowed_specific_char("*&%@#!}{"))
```

1.  答案：a。

`re`是标准库的一部分，可以使用`import re`导入。

1.  答案：a。

它将在开头查找模式，如果找不到则返回`None`。

1.  答案：d。

此函数返回整个匹配。

# 第八章，文档和报告

1.  主要区别在于当您使用`input`和`print`函数时，所有的输出格式化工作都是在幕后完成的。stdin 用于所有交互式输入，包括对`input()`的调用；stdout 用于`print()`和表达式语句的输出以及`input()`的提示。

1.  **简单邮件传输协议**（**SMTP**）是用于电子邮件传输的互联网标准。最初由 RFC 821 在 1982 年定义，2008 年通过 RFC 5321 进行了扩展 SMTP 的更新，这是今天广泛使用的协议。

1.  以下是答案：

```py
Hi Eric. You are a comedian. You were in Monty Python.
```

1.  以下是答案：

```py
str1 + str2 = HelloWorld!
str1 * 3 = HelloHelloHello
```

# 第九章，处理各种文件

1.  `f.readline()`从文件中读取一行；一个换行符（\n）留在字符串的末尾，并且只有在文件的最后一行没有换行符时才会被省略。如果要将文件的所有行读入列表中，还可以使用`list(f)`或`f.readlines()`。

1.  基本上，使用`with open()`只是确保您不会忘记`close()`文件，使其更安全/防止内存问题。

1.  `r`表示该字符串将被视为原始字符串。

1.  生成器简化了迭代器的创建。生成器是一个产生一系列结果而不是单个值的函数。

1.  在 Python 中，pass 语句用于在语法上需要语句但您不希望执行任何命令或代码时使用。pass 语句是一个空操作；执行时什么也不会发生。

1.  在 Python 中，匿名函数是在没有名称的情况下定义的函数。而普通函数是使用`def`关键字定义的，Python 中的匿名函数是使用`lambda`关键字定义的。因此，匿名函数也称为 lambda 函数。

# 第十章，基本网络 - 套接字编程

1.  套接字编程涉及编写计算机程序，使进程能够在计算机网络上相互通信。

1.  在分布式计算中，远程过程调用是指计算机程序导致在不同地址空间中执行过程，这是编码为正常过程调用，程序员不需要显式编码远程交互的细节。

1.  以下是答案：

```py
import filename (import file)
from filename import function1 (import specific function)
from filename import function1, function2(import multiple functions)
from filename import * (import all the functions)
```

1.  列表和元组之间的主要区别在于列表是可变的，而元组是不可变的。可变数据类型意味着可以修改此类型的 Python 对象。不可变意味着不能修改此类型的 Python 对象。

1.  你不能有一个带有重复键的字典，因为在后台它使用了一个哈希机制。

1.  `urllib`和`urllib2`都是执行 URL 请求相关操作的 Python 模块，但提供不同的功能。

`urllib2`可以接受一个请求对象来设置 URL 请求的标头，`urllib`只接受一个 URL。Python 请求会自动编码参数，因此您只需将它们作为简单参数传递。

# 第十一章，使用 Python 脚本处理电子邮件

1.  在计算中，邮局协议是一种应用层互联网标准协议，用于电子邮件客户端从邮件服务器检索电子邮件。 POP 版本 3 是常用的版本。**Internet Message Access Protocol**（**IMAP**）是一种互联网标准协议，用于电子邮件客户端通过 TCP/IP 连接从邮件服务器检索电子邮件消息。 IMAP 由 RFC 3501 定义。

1.  break 语句终止包含它的循环。程序的控制流流向循环体之后的语句。如果 break 语句在嵌套循环（一个循环内部的循环）中，break 将终止最内层的循环。以下是一个例子：

```py
for val in "string":
 if val == "i":
 break
 print(val)
print("The end")
```

1.  continue 语句用于仅跳过当前迭代中循环内部的其余代码。循环不会终止，而是继续下一个迭代：

```py
for val in "string":
 if val == "i":
 continue
 print(val)
print("The end")
```

1.  `pprint`模块提供了一种能够以可用作解释器输入的形式漂亮打印任意 Python 数据结构的功能。如果格式化的结构包括不是基本 Python 类型的对象，则表示可能无法加载。如果包括文件、套接字、类或实例等对象，以及许多其他无法表示为 Python 常量的内置对象，可能会出现这种情况。

1.  在 Python 中，负索引用于从列表、元组或支持索引的任何其他容器类的最后一个元素开始索引。`-1`指的是*最后一个索引*，`-2`指的是*倒数第二个索引*，依此类推。

1.  Python 编译`.py`文件并将其保存为`.pyc`文件，以便在后续调用中引用它们。`.pyc`包含 Python 源文件的已编译字节码。`.pyc`包含 Python 源文件的已编译字节码，这是 Python 解释器将源代码编译为的内容。然后，Python 的虚拟机执行此代码。删除`.pyc`不会造成任何损害，但如果要进行大量处理，它们将节省编译时间。

1.  以下是答案：

```py
num = 7
for index in range(num,0,-1):
if index % 2 != 0:
for row in range(0,num-index):
print(end=" ")
for row in range(0,index):
if row % 2== 0:
print("1",end=" ")
else:
print("0",end=" ")
print()
```

# 第十二章，通过 Telnet 和 SSH 远程监视主机

1.  客户端-服务器模型是一种分布式应用程序结构，它在资源或服务的提供者（称为服务器）和服务请求者（称为客户端）之间分配任务或工作负载。

1.  通过使用以下内容：

```py
os.commands(command_name)
subprocess.getstatusoutput(command_name)
```

1.  虚拟局域网是在数据链路层上分区和隔离的任何广播域，局域网是本地区域网络的缩写，在这种情况下，虚拟指的是通过附加逻辑重新创建和改变的物理对象。

1.  答案：`[]`。

它打印一个空列表，因为列表的大小小于 10。

1.  以下是答案：

```py
import calender
calendar.month(1,1)
```

1.  以下是答案：

```py
def file_lengthy(fname):
 with open(fname) as f:
 for i, l in enumerate(f):
 pass
 return i + 1
print("Number of lines in the file: ",file_lengthy("test.txt"))
```

# 第十三章，构建图形用户界面

1.  图形用户界面，允许用户与电子设备进行交互。

1.  构造函数是一种特殊类型的方法（函数），用于初始化类的实例成员。`__init__ 方法`的实现。析构函数是在对象销毁期间自动调用的特殊方法。`__del__ 方法`的实现。

1.  Self 是对对象本身的对象引用；因此，它们是相同的。

1.  Tkinter 是 Python 绑定到 Tk GUI 工具包的工具。它是 Tk GUI 工具包的标准 Python 接口，也是 Python 的事实标准 GUI。Tkinter 包含在标准的 Linux、Microsoft Windows 和 macOS X 的 Python 安装中。Tkinter 的名称来自 Tk 界面。PyQt 是跨平台 GUI 工具包 Qt 的 Python 绑定，实现为 Python 插件。PyQt 是由英国公司 Riverbank Computing 开发的免费软件。wxPython 是 Python 编程语言的跨平台 GUI API wxWidgets 的包装器。它是 Tkinter 的替代品之一，与 Python 捆绑在一起。它实现为 Python 扩展模块。其他流行的替代品是 PyGTK，它的后继者 PyGObject 和 PyQt。

1.  以下是答案：

```py
def copy(source, destination):
 with open(source, "w") as fw, open(destination,"r") as fr:
 fw.writelines(fr)
copy(source_file_name1, file_name2)
```

1.  以下是答案：

```py
fname = input("Enter file name: ")
l=input("Enter letter to be searched:")
k = 0
with open(fname, 'r') as f:
 for line in f:
 words = line.split()
 for i in words:
 for letter in i:
 if(letter==l):
 k=k+1
print("Occurrences of the letter:")
print(k)
```

# 第十四章，使用 Apache 和其他日志文件

1.  运行时异常发生在程序执行期间，它们会在中途突然退出。编译时异常是在程序执行开始之前发现的异常。

1.  正则表达式、regex 或 regexp 是定义搜索模式的字符序列。通常，这种模式由字符串搜索算法用于字符串的查找或查找和替换操作，或用于输入验证。

1.  以下是 Linux 命令的描述：

+   `head`：用于查看普通文件的前 N 行。

+   `tail`：用于查看普通文件的最后 N 行。

+   `cat`：用于查看普通文件的内容。

+   `awk`：AWK 是一种专为文本处理而设计的编程语言，通常用作数据提取和报告工具。它是大多数类 Unix 操作系统的标准功能。

1.  以下是答案：

```py
def append(source, destination):
 with open(source, "a") as fw, open(destination,"r") as fr:
 fw.writelines(fr)
append(source_file_name1, file_name2)
```

1.  以下是答案：

```py
filename=input("Enter file name: ")
for line in reversed(list(open(filename))):
 print(line.rstrip())
```

1.  表达式的输出如下：

1.  `C@ke`

1.  `Cooookie`

1.  `<h1>`

# 第十五章，SOAP 和 REST API 通信

1.  REST 基本上是 Web 服务的一种架构风格，它作为不同计算机或系统之间的通信渠道在互联网上工作。SOAP 是一种标准的通信协议系统，允许使用不同操作系统（如 Linux 和 Windows）的进程通过 HTTP 及其 XML 进行通信。基于 SOAP 的 API 旨在创建、恢复、更新和删除记录，如账户、密码、线索和自定义对象。

1.  `json.load`可以反序列化文件本身；也就是说，它接受文件对象。

1.  是的。JSON 是平台无关的。

1.  答案：false。

1.  答案：`{'x': 3}`。

# 第十六章，网络抓取-从网站提取有用数据

1.  Web 抓取、网络收集或网络数据提取是用于从网站提取数据的数据抓取。Web 抓取软件可以直接使用超文本传输协议访问万维网，也可以通过 Web 浏览器访问。

1.  Web 爬虫（也称为网络蜘蛛或网络机器人）是以一种有条理、自动化的方式浏览万维网的程序或自动化脚本。这个过程称为网络爬行或蜘蛛。

1.  是的。

1.  是的，使用 Tweepy。

1.  是的，通过使用 Selenium-Python 网络驱动程序。还有其他库可用，如 PhantomJS 和 dryscrape。

# 第十七章，统计收集和报告

1.  NumPy 的主要对象是同质多维数组。它是一张元素表（通常是数字），都是相同类型的，由正整数元组索引。在 NumPy 中，维度被称为轴。

1.  以下是输出：

```py
1st Input array : 
 [[ 1 2 3]
 [-1 -2 -3]]
2nd Input array : 
 [[ 4 5 6]
 [-4 -5 -6]]
Output stacked array :
 [[ 1 2 3 4 5 6]
 [-1 -2 -3 -4 -5 -6]]
```

1.  以下是答案：

```py
Z = np.arange(10)
np.add.reduce(Z)
```

1.  以下是答案：

```py
# Delete the rows with labels 0,1,5
data = data.drop([0,1,2], axis=0)
# Delete the first five rows using iloc selector
data = data.iloc[5:,]
#to delete the column
del df.column_name
```

1.  以下是答案：

```py
df.to_csv(“file_name.csv”,index=False, sep=”,”)
```

1.  **不是** **数字**（NaN），比如空值。在 pandas 中，缺失值用 NaN 表示。

1.  以下是答案：

```py
df.drop_duplicates()
```

1.  以下是答案：

```py
from matplotlib.pyplot import figure
figure(num=None, figsize=(8, 6), dpi=80, facecolor='w', edgecolor='k')
```

1.  Matplotlib、Plotly 和 Seaborn。

# 第十八章，MySQL 和 SQLite 数据库管理

1.  将数据存储在行和列中，并且可以轻松快速地执行不同的操作。

1.  在数据库中，CRUD 代表（创建，读取，更新，删除）。

1.  是的，这里有一个例子：

```py
MySQLdb.connect('remote_ip', 'username', 'password', 'databasename')
```

1.  是的。

1.  **DDL**代表**数据定义语言**。它用于定义数据结构。例如，使用 SQL，它将是创建表，修改表等指令。**DML**代表**数据操作语言**。它用于操作数据本身。例如，使用 SQL，它将是插入，更新和删除等指令。
