# PyTest 快速启动指南（二）

> 原文：[`zh.annas-archive.org/md5/ef4cd099dd041b2b3c7ad8b8d5fa4114`](https://zh.annas-archive.org/md5/ef4cd099dd041b2b3c7ad8b8d5fa4114)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：fixtures

在上一章中，我们学习了如何有效地使用标记和参数化来跳过测试，将其标记为预期失败，并对其进行参数化，以避免重复。

现实世界中的测试通常需要创建资源或数据来进行操作：一个临时目录来输出一些文件，一个数据库连接来测试应用程序的 I/O 层，一个用于集成测试的 Web 服务器。这些都是更复杂的测试场景中所需的资源的例子。更复杂的资源通常需要在测试会话结束时进行清理：删除临时目录，清理并断开与数据库的连接，关闭 Web 服务器。此外，这些资源应该很容易地在测试之间共享，因为在测试过程中我们经常需要为不同的测试场景重用资源。一些资源创建成本很高，但因为它们是不可变的或者可以恢复到原始状态，所以应该只创建一次，并与需要它的所有测试共享，在最后一个需要它们的测试完成时销毁。

pytest 最重要的功能之一是覆盖所有先前的要求和更多内容。

本章我们将涵盖以下内容：

+   引入 fixtures

+   使用`conftest.py`文件共享 fixtures

+   作用域

+   自动使用

+   参数化

+   使用 fixtures 中的标记

+   内置 fixtures 概述

+   提示/讨论

# 引入 fixtures

大多数测试需要某种数据或资源来操作：

```py
def test_highest_rated():
    series = [
        ("The Office", 2005, 8.8),
        ("Scrubs", 2001, 8.4),
        ("IT Crowd", 2006, 8.5),
        ("Parks and Recreation", 2009, 8.6),
        ("Seinfeld", 1989, 8.9),
    ]
    assert highest_rated(series) == "Seinfeld"
```

这里，我们有一个(`series name`, `year`, `rating`)元组的列表，我们用它来测试`highest_rated`函数。在这里将数据内联到测试代码中对于孤立的测试效果很好，但通常你会有一个可以被多个测试使用的数据集。一种解决方法是将数据集复制到每个测试中：

```py
def test_highest_rated():
    series = [
        ("The Office", 2005, 8.8),
        ...,
    ]
    assert highest_rated(series) == "Seinfeld"

def test_oldest():
    series = [
        ("The Office", 2005, 8.8),
        ...,
    ]
    assert oldest(series) == "Seinfeld"
```

但这很快就会变得老套—此外，复制和粘贴东西会在长期内影响可维护性，例如，如果数据布局发生变化（例如，添加一个新项目到元组或演员阵容大小）。

# 进入 fixtures

pytest 对这个问题的解决方案是 fixtures。fixtures 用于提供测试所需的函数和方法。

它们是使用普通的 Python 函数和`@pytest.fixture`装饰器创建的：

```py
@pytest.fixture
def comedy_series():
    return [
        ("The Office", 2005, 8.8),
        ("Scrubs", 2001, 8.4),
        ("IT Crowd", 2006, 8.5),
        ("Parks and Recreation", 2009, 8.6),
        ("Seinfeld", 1989, 8.9),
    ]
```

在这里，我们创建了一个名为`comedy_series`的 fixture，它返回我们在上一节中使用的相同列表。

测试可以通过在其参数列表中声明 fixture 名称来访问 fixtures。然后测试函数会接收 fixture 函数的返回值作为参数。这里是`comedy_series` fixture 的使用：

```py
def test_highest_rated(comedy_series):
    assert highest_rated(comedy_series) == "Seinfeld"

def test_oldest(comedy_series):
    assert oldest(comedy_series) == "Seinfeld"
```

事情是这样的：

+   pytest 在调用测试函数之前查看测试函数的参数。这里，我们有一个参数：`comedy_series`。

+   对于每个参数，pytest 获取相同名称的 fixture 函数并执行它。

+   每个 fixture 函数的返回值成为一个命名参数，并调用测试函数。

请注意，`test_highest_rated`和`test_oldest`各自获得喜剧系列列表的副本，因此如果它们在测试中更改列表，它们不会相互干扰。

还可以使用方法在类中创建 fixtures：

```py
class Test:

    @pytest.fixture
    def drama_series(self):
        return [
            ("The Mentalist", 2008, 8.1),
            ("Game of Thrones", 2011, 9.5),
            ("The Newsroom", 2012, 8.6),
            ("Cosmos", 1980, 9.3),
        ]
```

在测试类中定义的 fixtures 只能被类或子类的测试方法访问：

```py
class Test:
    ...

    def test_highest_rated(self, drama_series):
        assert highest_rated(drama_series) == "Game of Thrones"

    def test_oldest(self, drama_series):
        assert oldest(drama_series) == "Cosmos"
```

请注意，测试类可能有其他非测试方法，就像任何其他类一样。

# 设置/拆卸

正如我们在介绍中看到的，测试中使用的资源通常需要在测试完成后进行某种清理。

在我们之前的例子中，我们有一个非常小的数据集，所以在 fixture 中内联它是可以的。然而，假设我们有一个更大的数据集（比如，1000 个条目），那么在代码中写入它会影响可读性。通常，数据集在外部文件中，例如 CSV 格式，因此将其移植到 Python 代码中是一件痛苦的事情。

解决方法是将包含系列数据集的 CSV 文件提交到存储库中，并在测试中使用内置的`csv`模块进行读取；有关更多详细信息，请访问[`docs.python.org/3/library/csv.html`](https://docs.python.org/3/library/csv.html)。

我们可以更改`comedy_series` fixture 来实现这一点：

```py
@pytest.fixture
def comedy_series():
    file = open("series.csv", "r", newline="")
    return list(csv.reader(file))
```

这样做是有效的，但是我们作为认真的开发人员，希望能够正确关闭该文件。我们如何使用 fixtures 做到这一点呢？

Fixture 清理通常被称为**teardown**，并且可以使用`yield`语句轻松支持：

```py
@pytest.fixture
def some_fixture():
    value = setup_value()
    yield value
    teardown_value(value)
```

通过使用`yield`而不是`return`，会发生以下情况：

+   fixture 函数被调用

+   它执行直到 yield 语句，其中暂停并产生 fixture 值

+   测试执行，接收 fixture 值作为参数

+   无论测试是否通过，函数都会恢复执行，以执行其清理操作

对于熟悉它的人来说，这与**上下文管理器**（[`docs.python.org/3/library/contextlib.html#contextlib.contextmanager`](https://docs.python.org/3/library/contextlib.html#contextlib.contextmanager)）非常相似，只是您不需要用 try/except 子句将 yield 语句包围起来，以确保在发生异常时仍执行 yield 后的代码块。

让我们回到我们的例子；现在我们可以使用`yield`而不是`return`并关闭文件：

```py
@pytest.fixture
def comedy_series():
    file = open("series.csv", "r", newline="")
    yield list(csv.reader(file))
    file.close()
```

这很好，但请注意，因为`yield`与文件对象的`with`语句配合得很好，我们可以这样写：

```py
@pytest.fixture
def comedy_series():
    with open("series.csv", "r", newline="") as file:
        return list(csv.reader(file))
```

测试完成后，`with`语句会自动关闭文件，这更短，被认为更符合 Python 风格。

太棒了。

# 可组合性

假设我们收到一个新的 series.csv 文件，其中包含更多的电视系列，包括以前的喜剧系列和许多其他类型。我们希望为一些其他测试使用这些新数据，但我们希望保持现有的测试与以前一样工作。

在 pytest 中，fixture 可以通过声明它们为参数轻松依赖于其他 fixtures。利用这一特性，我们能够创建一个新的 series fixture，从`series.csv`中读取所有数据（现在包含更多类型），并将我们的`comedy_series` fixture 更改为仅过滤出喜剧系列：

```py
@pytest.fixture
def series():
    with open("series.csv", "r", newline="") as file:
        return list(csv.reader(file))

@pytest.fixture
def comedy_series(series):
    return [x for x in series if x[GENRE] == "comedy"]
```

使用`comedy_series`的测试保持不变：

```py
def test_highest_rated(comedy_series):
    assert highest_rated(comedy_series) == "Seinfeld"

def test_oldest(comedy_series):
    assert oldest(comedy_series) == "Seinfeld"
```

请注意，由于这些特性，fixtures 是依赖注入的一个典型例子，这是一种技术，其中函数或对象声明其依赖关系，但否则不知道或不关心这些依赖关系将如何创建，或者由谁创建。这使它们非常模块化和可重用。

# 使用 conftest.py 文件共享 fixtures

假设我们需要在其他测试模块中使用前一节中的`comedy_series` fixture。在 pytest 中，通过将 fixture 代码移动到`conftest.py`文件中，可以轻松共享 fixtures。

`conftest.py`文件是一个普通的 Python 模块，只是它会被 pytest 自动加载，并且其中定义的任何 fixtures 都会自动对同一目录及以下的测试模块可用。考虑一下这个测试模块的层次结构：

```py
tests/
    ratings/
        series.csv
        test_ranking.py
    io/
        conftest.py
        test_formats.py 
    conftest.py

```

`tests/conftest.py`文件位于层次结构的根目录，因此在该项目中，任何在其中定义的 fixtures 都会自动对所有其他测试模块可用。在`tests/io/conftest.py`中定义的 fixtures 将仅对`tests/io`及以下模块可用，因此目前仅对`test_formats.py`可用。

这可能看起来不像什么大不了的事，但它使共享 fixtures 变得轻而易举：当编写测试模块时，能够从小处开始使用一些 fixtures，知道如果将来这些 fixtures 对其他测试有用，只需将 fixtures 移动到`conftest.py`中即可。这避免了复制和粘贴测试数据的诱惑，或者花费太多时间考虑如何从一开始组织测试支持代码，以避免以后进行大量重构。

# 作用域

夹具总是在测试函数请求它们时创建的，通过在参数列表上声明它们，就像我们已经看到的那样。默认情况下，每个夹具在每个测试完成时都会被销毁。

正如本章开头提到的，一些夹具可能很昂贵，需要创建或设置，因此尽可能少地创建实例将非常有帮助，以节省时间。以下是一些示例：

+   初始化数据库表

+   例如，从磁盘读取缓存数据，大型 CSV 数据

+   启动外部服务

为了解决这个问题，pytest 中的夹具可以具有不同的**范围**。夹具的范围定义了夹具应该在何时清理。在夹具没有清理的情况下，请求夹具的测试将收到相同的夹具值。

`@pytest.fixture`装饰器的范围参数用于设置夹具的范围：

```py
@pytest.fixture(scope="session")
def db_connection():
    ...
```

以下范围可用：

+   `scope="session"`：当所有测试完成时，夹具被拆除。

+   `scope="module"`：当模块的最后一个测试函数完成时，夹具被拆除。

+   `scope="class"`：当类的最后一个测试方法完成时，夹具被拆除。

+   `scope="function"`：当请求它的测试函数完成时，夹具被拆除。这是默认值。

重要的是要强调，无论范围如何，每个夹具都只会在测试函数需要它时才会被创建。例如，会话范围的夹具不一定会在会话开始时创建，而是只有在第一个请求它的测试即将被调用时才会创建。当考虑到并非所有测试都可能需要会话范围的夹具，并且有各种形式只运行一部分测试时，这是有意义的，正如我们在前几章中所看到的。

# 范围的作用

为了展示作用域，让我们看一下在测试涉及某种数据库时使用的常见模式。在即将到来的示例中，不要关注数据库 API（无论如何都是虚构的），而是关注涉及的夹具的概念和设计。

通常，连接到数据库和表的创建都很慢。如果数据库支持事务，即执行可以原子地应用或丢弃的一组更改的能力，那么可以使用以下模式。

首先，我们可以使用会话范围的夹具连接和初始化我们需要的表的数据库：

```py
@pytest.fixture(scope="session")
def db():
    db = connect_to_db("localhost", "test") 
    db.create_table(Series)
    db.create_table(Actors)
    yield db
    db.prune()
    db.disconnect()
```

请注意，我们会在夹具结束时修剪测试数据库并断开与其的连接，这将在会话结束时发生。

通过`db`夹具，我们可以在所有测试中共享相同的数据库。这很棒，因为它节省了时间。但它也有一个缺点，现在测试可以更改数据库并影响其他测试。为了解决这个问题，我们创建了一个事务夹具，在测试开始之前启动一个新的事务，并在测试完成时回滚事务，确保数据库返回到其先前的状态：

```py
@pytest.fixture(scope="function")
def transaction(db):
    transaction = db.start_transaction()
    yield transaction
    transaction.rollback()
```

请注意，我们的事务夹具依赖于`db`。现在测试可以使用事务夹具随意读写数据库，而不必担心为其他测试清理它：

```py
def test_insert(transaction):
    transaction.add(Series("The Office", 2005, 8.8))
    assert transaction.find(name="The Office") is not None
```

有了这两个夹具，我们就有了一个非常坚实的基础来编写我们的数据库测试：需要事务夹具的第一个测试将通过`db`夹具自动初始化数据库，并且从现在开始，每个需要执行事务的测试都将从一个原始的数据库中执行。

不同范围夹具之间的可组合性非常强大，并且使得在现实世界的测试套件中可以实现各种巧妙的设计。

# 自动使用

可以通过将`autouse=True`传递给`@pytest.fixture`装饰器，将夹具应用于层次结构中的所有测试，即使测试没有明确请求夹具。当我们需要在每个测试之前和/或之后无条件地应用副作用时，这是有用的。

```py
@pytest.fixture(autouse=True)
def setup_dev_environment():
    previous = os.environ.get('APP_ENV', '')
    os.environ['APP_ENV'] = 'TESTING'
    yield
    os.environ['APP_ENV'] = previous
```

自动使用的夹具适用于夹具可供使用的所有测试：

+   与夹具相同的模块

+   在方法定义的情况下，与装置相同的类。

+   如果装置在`conftest.py`文件中定义，那么在相同目录或以下目录中的测试

换句话说，如果一个测试可以通过在参数列表中声明它来访问一个`autouse`装置，那么该测试将自动使用`autouse`装置。请注意，如果测试函数对装置的返回值感兴趣，它可能会将`autouse`装置添加到其参数列表中，就像正常情况一样。

# @pytest.mark.usefixtures

`@pytest.mark.usefixtures`标记可用于将一个或多个装置应用于测试，就好像它们在参数列表中声明了装置名称一样。在您希望所有组中的测试始终使用不是`autouse`的装置的情况下，这可能是一种替代方法。

例如，下面的代码将确保`TestVirtualEnv`类中的所有测试方法在一个全新的虚拟环境中执行：

```py
@pytest.fixture
def venv_dir():
    import venv

    with tempfile.TemporaryDirectory() as d:
        venv.create(d)
        pwd = os.getcwd()
        os.chdir(d)
        yield d
        os.chdir(pwd)

@pytest.mark.usefixtures('venv_dir')
class TestVirtualEnv:
    ...
```

正如名称所示，您可以将多个装置名称传递给装饰器：

```py
@pytest.mark.usefixtures("venv_dir", "config_python_debug")
class Test:
    ...
```

# 参数化装置

装置也可以直接进行参数化。当一个装置被参数化时，所有使用该装置的测试现在将多次运行，每个参数运行一次。当我们有装置的变体，并且每个使用该装置的测试也应该与所有变体一起运行时，这是一个很好的工具。

在上一章中，我们看到了使用序列化器的多个实现进行参数化的示例：

```py
@pytest.mark.parametrize(
    "serializer_class",
    [JSONSerializer, XMLSerializer, YAMLSerializer],
)
class Test:

    def test_quantity(self, serializer_class):
        serializer = serializer_class()
        quantity = Quantity(10, "m")
        data = serializer.serialize_quantity(quantity)
        new_quantity = serializer.deserialize_quantity(data)
        assert new_quantity == quantity

    def test_pipe(self, serializer_class):
        serializer = serializer_class()
        pipe = Pipe(
            length=Quantity(1000, "m"), diameter=Quantity(35, "cm")
        )
       data = serializer.serialize_pipe(pipe)
       new_pipe = serializer.deserialize_pipe(data)
       assert new_pipe == pipe
```

我们可以更新示例以在装置上进行参数化：

```py
class Test:

 @pytest.fixture(params=[JSONSerializer, XMLSerializer,
 YAMLSerializer])
 def serializer(self, request):
 return request.param()

    def test_quantity(self, serializer):
        quantity = Quantity(10, "m")
        data = serializer.serialize_quantity(quantity)
        new_quantity = serializer.deserialize_quantity(data)
        assert new_quantity == quantity

    def test_pipe(self, serializer):
        pipe = Pipe(
            length=Quantity(1000, "m"), diameter=Quantity(35, "cm")
        )
        data = serializer.serialize_pipe(pipe)
        new_pipe = serializer.deserialize_pipe(data)
        assert new_pipe == pipe
```

请注意以下内容：

+   我们向装置定义传递了一个`params`参数。

+   我们使用`request`对象的特殊`param`属性在装置内部访问参数。当装置被参数化时，这个内置装置提供了对请求测试函数和参数的访问。我们将在本章后面更多地了解`request`装置。

+   在这种情况下，我们在装置内部实例化序列化器，而不是在每个测试中显式实例化。

可以看到，参数化装置与参数化测试非常相似，但有一个关键的区别：通过参数化装置，我们使所有使用该装置的测试针对所有参数化的实例运行，使它们成为`conftest.py`文件中共享的装置的绝佳解决方案。

当您向现有装置添加新参数时，看到自动执行了许多新测试是非常有益的。

# 使用装置标记

我们可以使用`request`装置来访问应用于测试函数的标记。

假设我们有一个`autouse`装置，它总是将当前区域初始化为英语：

```py
@pytest.fixture(autouse=True)
def setup_locale():
    locale.setlocale(locale.LC_ALL, "en_US")
    yield
    locale.setlocale(locale.LC_ALL, None)

def test_currency_us():
    assert locale.currency(10.5) == "$10.50"
```

但是，如果我们只想为一些测试使用不同的区域设置呢？

一种方法是使用自定义标记，并在我们的装置内部访问`mark`对象：

```py
@pytest.fixture(autouse=True)
def setup_locale(request):
    mark = request.node.get_closest_marker("change_locale")
    loc = mark.args[0] if mark is not None else "en_US"
    locale.setlocale(locale.LC_ALL, loc)
    yield
    locale.setlocale(locale.LC_ALL, None)

@pytest.mark.change_locale("pt_BR")
def test_currency_br():
    assert locale.currency(10.5) == "R$ 10,50"
```

标记可以用来将信息传递给装置。因为它有点隐式，所以我建议节俭使用，因为它可能导致难以理解的代码。

# 内置装置概述

让我们来看一些内置的 pytest 装置。

# tmpdir

`tmpdir`装置提供了一个在每次测试结束时自动删除的空目录：

```py
def test_empty(tmpdir):
    assert os.path.isdir(tmpdir)
    assert os.listdir(tmpdir) == []
```

作为`function`-scoped 装置，每个测试都有自己的目录，因此它们不必担心清理或生成唯一的目录。

装置提供了一个`py.local`对象（[`py.readthedocs.io/en/latest/path.html`](http://py.readthedocs.io/en/latest/path.html)），来自`py`库（[`py.readthedocs.io`](http://py.readthedocs.io)），它提供了方便的方法来处理文件路径，比如连接，读取，写入，获取扩展名等等；它在哲学上类似于标准库中的`pathlib.Path`对象（[`docs.python.org/3/library/pathlib.html`](https://docs.python.org/3/library/pathlib.html)）：

```py
def test_save_curves(tmpdir):
    data = dict(status_code=200, values=[225, 300])
    fn = tmpdir.join('somefile.json')
    write_json(fn, data)
    assert fn.read() == '{"status_code": 200, "values": [225, 300]}'
```

为什么 pytest 使用`py.local`而不是`pathlib.Path`？

在`pathlib.Path`出现并被合并到标准库之前，Pytest 已经存在多年了，而`py`库是当时路径类对象的最佳解决方案之一。核心 pytest 开发人员正在研究如何使 pytest 适应现在标准的`pathlib.Path`API。

# tmpdir_factory

`tmpdir`装置非常方便，但它只有`function`*-*scoped：这样做的缺点是它只能被其他`function`-scoped 装置使用。

`tmpdir_factory`装置是一个*session-scoped*装置，允许在任何范围内创建空的唯一目录。当我们需要在其他范围的装置中存储数据时，例如`session`-scoped 缓存或数据库文件时，这可能很有用。

为了展示它的作用，接下来显示的`images_dir`装置使用`tmpdir_factory`创建一个唯一的目录，整个测试会话中包含一系列示例图像文件：

```py
@pytest.fixture(scope='session')
def images_dir(tmpdir_factory):
    directory = tmpdir_factory.mktemp('images')
    download_images('https://example.com/samples.zip', directory)
    extract_images(directory / 'samples.zip')
    return directory
```

因为这将每个会话只执行一次，所以在运行测试时会节省我们相当多的时间。

然后测试可以使用`images_dir`装置轻松访问示例图像文件：

```py
def test_blur_filter(images_dir):
    output_image = apply_blur_filter(images_dir / 'rock1.png')
    ...
```

但请记住，此装置创建的目录是共享的，并且只会在测试会话结束时被删除。这意味着测试不应修改目录的内容；否则，它们可能会影响其他测试。

# 猴子补丁

在某些情况下，测试需要复杂或难以在测试环境中设置的功能，例如：

+   对外部资源的客户端（例如 GitHub 的 API）需要在测试期间访问可能不切实际或成本太高

+   强制代码表现得好像在另一个平台上，比如错误处理

+   复杂的条件或难以在本地或 CI 中重现的环境

`monkeypatch`装置允许您使用其他对象和函数干净地覆盖正在测试的系统的函数、对象和字典条目，并在测试拆卸期间撤消所有更改。例如：

```py
import getpass

def user_login(name):
    password = getpass.getpass()
    check_credentials(name, password)
    ...
```

在这段代码中，`user_login`使用标准库中的`getpass.getpass()`函数（[`docs.python.org/3/library/getpass.html`](https://docs.python.org/3/library/getpass.html)）以系统中最安全的方式提示用户输入密码。在测试期间很难模拟实际输入密码，因为`getpass`尝试直接从终端读取（而不是从`sys.stdin`）。

我们可以使用`monkeypatch`装置来在测试中绕过对`getpass`的调用，透明地而不改变应用程序代码：

```py
def test_login_success(monkeypatch):
    monkeypatch.setattr(getpass, "getpass", lambda: "valid-pass")
    assert user_login("test-user")

def test_login_wrong_password(monkeypatch):
    monkeypatch.setattr(getpass, "getpass", lambda: "wrong-pass")
    with pytest.raises(AuthenticationError, match="wrong password"):
        user_login("test-user")
```

在测试中，我们使用`monkeypatch.setattr`来用一个虚拟的`lambda`替换`getpass`模块的真实`getpass()`函数，它返回一个硬编码的密码。在`test_login_success`中，我们返回一个已知的好密码，以确保用户可以成功进行身份验证，而在`test_login_wrong_password`中，我们使用一个错误的密码来确保正确处理身份验证错误。如前所述，原始的`getpass()`函数会在测试结束时自动恢复，确保我们不会将该更改泄漏到系统中的其他测试中。

# 如何和在哪里修补

`monkeypatch`装置通过用另一个对象（通常称为*模拟*）替换对象的属性来工作，在测试结束时恢复原始对象。使用此装置的常见问题是修补错误的对象，这会导致调用原始函数/对象而不是模拟函数/对象。

要理解问题，我们需要了解 Python 中`import`和`import from`的工作原理。

考虑一个名为`services.py`的模块：

```py
import subprocess

def start_service(service_name):
    subprocess.run(f"docker run {service_name}")
```

在这段代码中，我们导入`subprocess`模块并将`subprocess`模块对象引入`services.py`命名空间。这就是为什么我们调用`subprocess.run`：我们正在访问`services.py`命名空间中`subprocess`对象的`run`函数。

现在考虑稍微不同的以前的代码写法：

```py
from subprocess import run

def start_service(service_name):
    run(f"docker run {service_name}")
```

在这里，我们导入了`subprocess`模块，但将`run`函数对象带入了`service.py`命名空间。这就是为什么`run`可以直接在`start_service`中调用，而`subprocess`名称甚至不可用（如果尝试调用`subprocess.run`，将会得到`NameError`异常）。

我们需要意识到这种差异，以便正确地`monkeypatch`在`services.py`中使用`subprocess.run`。

在第一种情况下，我们需要替换`subprocess`模块的`run`函数，因为`start_service`就是这样使用它的：

```py
import subprocess
import services

def test_start_service(monkeypatch):
    commands = []
    monkeypatch.setattr(subprocess, "run", commands.append)
    services.start_service("web")
    assert commands == ["docker run web"]
```

在这段代码中，`services.py`和`test_services.py`都引用了相同的`subprocess`模块对象。

然而，在第二种情况下，`services.py`在自己的命名空间中引用了原始的`run`函数。因此，第二种情况的正确方法是替换`services.py`命名空间中的`run`函数：

```py
import services

def test_start_service(monkeypatch):
    commands = []
    monkeypatch.setattr(services, "run", commands.append)
    services.start_service("web")
    assert commands == ["docker run web"]
```

被测试代码导入需要进行 monkeypatch 的代码是人们经常被绊倒的原因，所以确保您首先查看代码。

# capsys/capfd

`capsys` fixture 捕获了写入`sys.stdout`和`sys.stderr`的所有文本，并在测试期间使其可用。

假设我们有一个小的命令行脚本，并且希望在调用脚本时没有参数时检查使用说明是否正确：

```py
from textwrap import dedent

def script_main(args):
    if not args:
        show_usage()
        return 0
    ...

def show_usage():
    print("Create/update webhooks.")
    print(" Usage: hooks REPO URL")
```

在测试期间，我们可以使用`capsys` fixture 访问捕获的输出。这个 fixture 有一个`capsys.readouterr()`方法，返回一个`namedtuple`([`docs.python.org/3/library/collections.html#collections.namedtuple`](https://docs.python.org/3/library/collections.html#collections.namedtuple))，其中包含从`sys.stdout`和`sys.stderr`捕获的文本。

```py
def test_usage(capsys):
    script_main([])
    captured = capsys.readouterr()
    assert captured.out == dedent("""\
        Create/update webhooks.
          Usage: hooks REPO URL
    """)
```

还有`capfd` fixture，它的工作方式类似于`capsys`，只是它还捕获文件描述符`1`和`2`的输出。这使得可以捕获标准输出和标准错误，即使是对于扩展模块。

# 二进制模式

`capsysbinary`和`capfdbinary`是与`capsys`和`capfd`相同的 fixtures，不同之处在于它们以二进制模式捕获输出，并且它们的`readouterr()`方法返回原始字节而不是文本。在特殊情况下可能会有用，例如运行生成二进制输出的外部进程时，如`tar`。

# request

`request` fixture 是一个内部 pytest fixture，提供有关请求测试的有用信息。它可以在测试函数和 fixtures 中声明，并提供以下属性：

+   `function`：Python `test`函数对象，可用于`function`-scoped fixtures。

+   `cls`/`instance`：Python 类/实例的`test`方法对象，可用于`function`和`class`-scoped fixtures。如果 fixture 是从`test`函数请求的，而不是测试方法，则可以为`None`。

+   `module`：请求测试方法的 Python 模块对象，可用于`module`，`function`和`class`-scoped fixtures。

+   `session`：pytest 的内部`Session`对象，它是测试会话的单例，代表集合树的根。它可用于所有范围的 fixtures。

+   `node`：pytest 集合节点，它包装了与 fixture 范围匹配的 Python 对象之一。

+   `addfinalizer(func)`: 添加一个将在测试结束时调用的`new finalizer`函数。finalizer 函数将在不带参数的情况下调用。`addfinalizer`是在 fixtures 中执行拆卸的原始方法，但后来已被`yield`语句取代，主要用于向后兼容。

fixtures 可以使用这些属性根据正在执行的测试自定义自己的行为。例如，我们可以创建一个 fixture，使用当前测试名称作为临时目录的前缀，类似于内置的`tmpdir` fixture：

```py
@pytest.fixture
def tmp_path(request) -> Path:
    with TemporaryDirectory(prefix=request.node.name) as d:
        yield Path(d)

def test_tmp_path(tmp_path):
    assert list(tmp_path.iterdir()) == []
```

在我的系统上执行此代码时创建了以下目录：

```py
C:\Users\Bruno\AppData\Local\Temp\test_tmp_patht5w0cvd0
```

`request` fixture 可以在您想要根据正在执行的测试的属性自定义 fixture，或者访问应用于测试函数的标记时使用，正如我们在前面的部分中所看到的。

# 提示/讨论

以下是一些未适应前面部分的短话题和提示，但我认为值得一提。

# 何时使用 fixture，而不是简单函数

有时，您只需要为测试构造一个简单的对象，可以说这可以通过一个普通函数来完成，不一定需要实现为 fixture。假设我们有一个不接收任何参数的 `WindowManager` 类：

```py
class WindowManager:
    ...
```

在我们的测试中使用它的一种方法是编写一个 fixture：

```py
@pytest.fixture
def manager():
 return WindowManager()

def test_windows_creation(manager):
    window = manager.new_help_window("pipes_help.rst")
    assert window.title() == "Pipe Setup Help"
```

或者，您可以主张为这样简单的用法编写一个 fixture 是过度的，并且使用一个普通函数代替：

```py
def create_window_manager():
    return WindowManager()

def test_windows_creation():
    manager = create_window_manager()
    window = manager.new_help_window("pipes_help.rst")
    assert window.title() == "Pipe Setup Help"
```

或者您甚至可以在每个测试中显式创建管理器：

```py
def test_windows_creation():
    manager = WindowManager()
    window = manager.new_help_window("pipes_help.rst")
    assert window.title() == "Pipe Setup Help"
```

这是完全可以的，特别是如果在单个模块中的少数测试中使用。

然而，请记住，fixture **抽象了对象的构建和拆卸过程的细节**。在决定放弃 fixture 而选择普通函数时，这一点至关重要。

假设我们的 `WindowManager` 现在需要显式关闭，或者它需要一个本地目录用于记录目的：

```py
class WindowManager:

    def __init__(self, logging_directory):
        ...

    def close(self):
        """
        Close the WindowManager and all associated resources. 
        """
        ...
```

如果我们一直在使用像第一个例子中给出的 fixture，我们只需更新 fixture 函数，**测试根本不需要改变**：

```py
@pytest.fixture
def manager(tmpdir):
    wm = WindowManager(str(tmpdir))
    yield wm
 wm.close()
```

但是，如果我们选择使用一个普通函数，现在我们**必须更新调用我们函数的所有地方**：我们需要传递一个记录目录，并确保在测试结束时调用 `.close()`：

```py
def create_window_manager(tmpdir, request):
    wm = WindowManager(str(tmpdir))
    request.addfinalizer(wm.close)
    return wm

def test_windows_creation(tmpdir, request):
    manager = create_window_manager(tmpdir, request)
    window = manager.new_help_window("pipes_help.rst")
    assert window.title() == "Pipe Setup Help"
```

根据这个函数在我们的测试中被使用的次数，这可能是一个相当大的重构。

这个信息是：当底层对象简单且不太可能改变时，使用普通函数是可以的，但请记住，fixture 抽象了对象的创建/销毁的细节，它们可能在将来需要更改。另一方面，使用 fixture 创建了另一个间接层，稍微增加了代码复杂性。最终，这是一个需要您权衡的平衡。

# 重命名 fixture

`@pytest.fixture` 装饰器接受一个 `name` 参数，该参数可用于指定 fixture 的名称，与 fixture 函数不同：

```py
@pytest.fixture(name="venv_dir")
def _venv_dir():
    ...
```

这是有用的，因为有一些烦恼可能会影响用户在使用在相同模块中声明的 fixture 时：

+   如果用户忘记在测试函数的参数列表中声明 fixture，他们将得到一个 `NameError`，而不是 fixture 函数对象（因为它们在同一个模块中）。

+   一些 linters 抱怨测试函数参数遮蔽了 fixture 函数。

如果之前的烦恼经常发生，您可能会将这视为团队中的一个良好实践。请记住，这些问题只会发生在测试模块中定义的 fixture 中，而不会发生在 `conftest.py` 文件中。

# 在 conftest 文件中优先使用本地导入

`conftest.py` 文件在收集期间被导入，因此它们直接影响您从命令行运行测试时的体验。因此，我建议在 `conftest.py` 文件中尽可能使用本地导入，以保持导入时间较短。

因此，不要使用这个：

```py
import pytest
import tempfile
from myapp import setup

@pytest.fixture
def setup_app():
    ...
```

优先使用本地导入：

```py
import pytest

@pytest.fixture
def setup_app():
 import tempfile
 from myapp import setup
    ...
```

这种做法对大型测试套件的启动有明显影响。

# fixture 作为测试支持代码

您应该将 fixture 视为不仅提供资源的手段，还提供测试的支持代码。通过支持代码，我指的是为测试提供高级功能的类。

例如，一个机器人框架可能会提供一个 fixture，用于测试您的机器人作为黑盒：

```py
def test_hello(bot):
    reply = bot.say("hello")
    assert reply.text == "Hey, how can I help you?"

def test_store_deploy_token(bot):
    assert bot.store["TEST"]["token"] is None
    reply = bot.say("my token is ASLKM8KJAN")
    assert reply.text == "OK, your token was saved"
    assert bot.store["TEST"]["token"] == "ASLKM8KJAN"
```

`bot` fixture 允许开发人员与机器人交谈，验证响应，并检查框架处理的内部存储的内容，等等。它提供了一个高级接口，使得测试更容易编写和理解，即使对于那些不了解框架内部的人也是如此。

这种技术对应用程序很有用，因为它将使开发人员轻松愉快地添加新的测试。对于库来说也很有用，因为它们将为库的用户提供高级测试支持。

# 总结

在本章中，我们深入了解了 pytest 最著名的功能之一：fixtures。我们看到了它们如何被用来提供资源和测试功能，以及如何简洁地表达设置/拆卸代码。我们学会了如何共享 fixtures，使用`conftest.py`文件；如何使用 fixture scopes，避免为每个测试创建昂贵的资源；以及如何自动使用 fixtures，这些 fixtures 会在同一模块或层次结构中的所有测试中执行。然后，我们学会了如何对 fixtures 进行参数化，并从中使用标记。我们对各种内置 fixtures 进行了概述，并在最后对 fixtures 进行了一些简短的讨论。希望您喜欢这一过程！

在下一章中，我们将探索一下广阔的 pytest 插件生态系统，这些插件都可以供您使用。


# 第四章：插件

在前一章中，我们探讨了 pytest 最重要的特性之一：fixture。我们学会了如何使用 fixture 来管理资源，并在编写测试时让我们的生活更轻松。

pytest 是以定制和灵活性为目标构建的，并允许开发人员编写称为**插件**的强大扩展。pytest 中的插件可以做各种事情，从简单地提供新的 fixture，到添加命令行选项，改变测试的执行方式，甚至运行用其他语言编写的测试。

在本章中，我们将做以下事情：

+   学习如何查找和安装插件

+   品尝生态系统提供的插件

# 查找和安装插件

正如本章开头提到的，pytest 是从头开始以定制和灵活性为目标编写的。插件机制是 pytest 架构的核心，以至于 pytest 的许多内置功能都是以内部插件的形式实现的，比如标记、参数化、fixture——几乎所有东西，甚至命令行选项。

这种灵活性导致了一个庞大而丰富的插件生态系统。在撰写本文时，可用的插件数量已经超过 500 个，而且这个数字以惊人的速度不断增加。

# 查找插件

考虑到插件的数量众多，如果有一个网站能够展示所有 pytest 插件以及它们的描述，那将是很好的。如果这个地方还能显示关于不同 Python 和 pytest 版本的兼容性信息，那就更好了。

好消息是，这样的网站已经存在了，并且由核心开发团队维护：pytest 插件兼容性（[`plugincompat.herokuapp.com/`](http://plugincompat.herokuapp.com/)）。在这个网站上，你将找到 PyPI 中所有可用的 pytest 插件的列表，以及 Python 和 pytest 版本的兼容性信息。该网站每天都会从 PyPI 直接获取新的插件和更新，是一个浏览新插件的好地方。

# 安装插件

插件通常使用`pip`安装：

```py
λ pip install <PLUGIN_NAME>
```

例如，要安装`pytest-mock`，我们执行以下操作：

```py
λ pip install pytest-mock
```

不需要任何注册；pytest 会自动检测你的虚拟环境或 Python 安装中安装的插件。

这种简单性使得尝试新插件变得非常容易。

# 各种插件概述

现在，我们将看一些有用和/或有趣的插件。当然，不可能在这里覆盖所有的插件，所以我们将尝试覆盖那些涵盖流行框架和一般功能的插件，还有一些晦涩的插件。当然，这只是皮毛，但让我们开始吧。

# pytest-xdist

这是一个非常受欢迎的插件，由核心开发人员维护；它允许你在多个 CPU 下运行测试，以加快测试运行速度。

安装后，只需使用`-n`命令行标志来使用给定数量的 CPU 来运行测试：

```py
λ pytest -n 4
```

就是这样！现在，你的测试将在四个核心上运行，希望能够加快测试套件的速度，如果测试是 CPU 密集型的话，尽管 I/O 绑定的测试不会看到太多改进。你也可以使用`-n auto`来让`pytest-xdist`自动计算出你可用的 CPU 数量。

请记住，当你的测试并行运行，并且以随机顺序运行时，它们必须小心避免相互干扰，例如，读/写到同一个目录。虽然它们应该是幂等的，但以随机顺序运行测试通常会引起之前潜伏的问题。

# pytest-cov

`pytest-cov`插件与流行的 coverage 模块集成，当运行测试时提供详细的覆盖报告。这让你可以检测到没有被任何测试代码覆盖的代码部分，这是一个机会，可以编写更多的测试来覆盖这些情况。

安装后，您可以使用`--cov`选项在测试运行结束时提供覆盖报告：

```py
λ pytest --cov=src
...
----------- coverage: platform win32, python 3.6.3-final-0 -----------
Name                  Stmts   Miss  Cover
----------------------------------------
src/series.py           108      5   96%
src/tests/test_series    22      0  100%
----------------------------------------
TOTAL                   130      5   97%
```

`--cov`选项接受应生成报告的源文件路径，因此根据项目的布局，您应传递您的`src`或包目录。

您还可以使用`--cov-report`选项以生成各种格式的报告：XML，annotate 和 HTML。后者特别适用于本地使用，因为它生成 HTML 文件，显示您的代码，未覆盖的行以红色突出显示，非常容易找到这些未覆盖的地方。

此插件还可以与`pytest-xdist`直接使用。

最后，此插件生成的`.coverage`文件与许多提供覆盖跟踪和报告的在线服务兼容，例如`coveralls.io`（[`coveralls.io/`](https://coveralls.io/)）和`codecov.io`（[`codecov.io/`](https://codecov.io/)）。

# pytest-faulthandler

此插件在运行测试时自动启用内置的`faulthandler`（[`docs.python.org/3/library/faulthandler.html`](https://docs.python.org/3/library/faulthandler.html)）模块，该模块在灾难性情况下（如分段错误）输出 Python 回溯。安装后，无需其他设置或标志；`faulthandler`模块将自动启用。

如果您经常使用用 C/C++编写的扩展模块，则强烈建议使用此插件，因为这些模块更容易崩溃。

# pytest-mock

`pytest-mock`插件提供了一个 fixture，允许 pytest 和标准库的`unittest.mock`（[`docs.python.org/3/library/unittest.mock.html`](https://docs.python.org/3/library/unittest.mock.html)）模块之间更顺畅地集成。它提供了类似于内置的`monkeypatch` fixture 的功能，但是`unittest.mock`产生的模拟对象还记录有关它们如何被访问的信息。这使得许多常见的测试任务更容易，例如验证已调用模拟函数以及使用哪些参数。

该插件提供了一个`mocker` fixture，可用于修补类和方法。使用上一章中的`getpass`示例，以下是您可以使用此插件编写它的方式：

```py
import getpass

def test_login_success(mocker):
    mocked = mocker.patch.object(getpass, "getpass", 
                                 return_value="valid-pass")
    assert user_login("test-user")
    mocked.assert_called_with("enter password: ")
```

请注意，除了替换`getpass.getpass()`并始终返回相同的值之外，我们还可以确保`getpass`函数已使用正确的参数调用。

在使用此插件时，与上一章中如何以及在哪里修补`monkeypatch` fixture 的建议也适用。

# pytest-django

顾名思义，此插件允许您使用 pytest 测试您的`Django`（[`www.djangoproject.com/`](https://www.djangoproject.com/)）应用程序。`Django`是当今最著名的 Web 框架之一。

该插件提供了大量功能：

+   一个非常好的快速入门教程

+   命令行和`pytest.ini`选项来配置 Django

+   与`pytest-xdist`兼容

+   使用`django_db`标记访问数据库，在测试之间自动回滚事务，以及一堆 fixture，让您控制数据库的管理方式

+   用于向应用程序发出请求的 fixture：`client`，`admin_client`和`admin_user`

+   在后台线程中运行`Django`服务器的`live_server` fixture

总的来说，这是生态系统中最完整的插件之一，具有太多功能无法在此处覆盖。对于`Django`应用程序来说，这是必不可少的，因此请务必查看其广泛的文档。

# pytest-flakes

此插件允许您使用`pyflakes`（[`pypi.org/project/pyflakes/`](https://pypi.org/project/pyflakes/)）检查您的代码，这是一个用于常见错误的源文件的静态检查器，例如丢失的导入和未知变量。

安装后，使用`--flakes`选项来激活它：

```py
λ pytest pytest-flakes.py --flake
...
============================= FAILURES ==============================
__________________________ pyflakes-check ___________________________
CH5\pytest-flakes.py:1: UnusedImport
'os' imported but unused
CH5\pytest-flakes.py:6: UndefinedName
undefined name 'unknown'
```

这将在你的正常测试中运行 flake 检查，使其成为保持代码整洁和防止一些错误的简单而廉价的方法。该插件还保留了自上次检查以来未更改的文件的本地缓存，因此在本地使用起来快速和方便。

# pytest-asyncio

`asyncio` ([`docs.python.org/3/library/asyncio.html`](https://docs.python.org/3/library/asyncio.html))模块是 Python 3 的热门新功能之一，提供了一个新的用于异步应用程序的框架。`pytest-asyncio`插件让你编写异步测试函数，轻松测试你的异步代码。

你只需要将你的测试函数标记为`async def`并使用`asyncio`标记：

```py
@pytest.mark.asyncio
async def test_fetch_requests():
    requests = await fetch_requests("example.com/api")
    assert len(requests) == 2
```

该插件还在后台管理事件循环，提供了一些选项，以便在需要使用自定义事件循环时进行更改。

当然，你可以在异步函数之外拥有正常的同步测试函数。

# pytest-trio

Trio 的座右铭是“Pythonic async I/O for humans” ([`trio.readthedocs.io/en/latest/`](https://trio.readthedocs.io/en/latest/))。它使用与`asyncio`标准模块相同的`async def`/`await`关键字，但被认为更简单和更友好，包含一些关于如何处理超时和一组并行任务的新颖想法，以避免并行编程中的常见错误。如果你对异步开发感兴趣，它绝对值得一试。

`pytest-trio`的工作方式类似于`pytest-asyncio`：你编写异步测试函数，并使用`trio`标记它们。它还提供了其他功能，使测试更容易和更可靠，例如可控的时钟用于测试超时，处理任务的特殊函数，模拟网络套接字和流，以及更多。

# pytest-tornado

Tornado ([`www.tornadoweb.org/en/stable/`](http://www.tornadoweb.org/en/stable/))是一个 Web 框架和异步网络库。它非常成熟，在 Python 2 和 3 中工作，标准的`asyncio`模块从中借鉴了许多想法和概念。

`pytest-asyncio`受`pytest-tornado`的启发，因此它使用相同的想法，使用`gen_test`来标记你的测试为协程。它使用`yield`关键字而不是`await`，因为它支持 Python 2，但除此之外它看起来非常相似：

```py
@pytest.mark.gen_test
def test_tornado(http_client):
    url = "https://docs.pytest.org/en/latest"
    response = yield http_client.fetch(url)
    assert response.code == 200
```

# pytest-postgresql

该插件允许你测试需要运行的 PostgreSQL 数据库的代码。

以下是它的一个快速示例：

```py
def test_fetch_series(postgresql):
    cur = postgresql.cursor()
    cur.execute('SELECT * FROM comedy_series;')
    assert len(cur.fetchall()) == 5
    cur.close()
```

它提供了两个 fixtures：

+   `postgresql`：一个客户端 fixture，启动并关闭到正在运行的测试数据库的连接。在测试结束时，它会删除测试数据库，以确保测试不会相互干扰。

+   `postgresql_proc`：一个会话范围的 fixture，每个会话启动一次 PostgreSQL 进程，并确保在结束时停止。

它还提供了几个配置选项，用于连接和配置测试数据库。

# docker-services

该插件启动和管理你需要的 Docker 服务，以便测试你的代码。这使得运行测试变得简单，因为你不需要手动启动服务；插件将在测试会话期间根据需要启动和停止它们。

你可以使用`.services.yaml`文件来配置服务；这里是一个简单的例子：

```py
database:
    image: postgres
    environment:
        POSTGRES_USERNAME: pytest-user
        POSTGRES_PASSWORD: pytest-pass
        POSTGRES_DB: test
    image: regis:10 
```

这将启动两个服务：`postgres`和`redis`。

有了这个，剩下的就是用以下命令运行你的套件：

```py
pytest --docker-services
```

插件会处理剩下的事情。

# pytest-selenium

Selenium 是一个针对自动化浏览器的框架，用于测试 Web 应用程序 ([`www.seleniumhq.org/`](https://www.seleniumhq.org/))。它可以做诸如打开网页、点击按钮，然后确保某个页面加载等事情。它支持所有主流浏览器，并拥有一个蓬勃发展的社区。

`pytest-selenium`提供了一个 fixture，让你编写测试来完成所有这些事情，它会为你设置`Selenium`。

以下是如何访问页面，点击链接并检查加载页面的标题的基本示例：

```py
def test_visit_pytest(selenium):
    selenium.get("https://docs.pytest.org/en/latest/")
    assert "helps you write better programs" in selenium.title
    elem = selenium.find_element_by_link_text("Contents")
    elem.click()
    assert "Full pytest documentation" in selenium.title
```

`Selenium`和`pytest-selenium`足够复杂，可以测试从静态页面到完整的单页前端应用程序的各种应用。

# pytest-html

`pytest-html` 生成美丽的 HTML 测试结果报告。安装插件后，只需运行以下命令：

```py
λ pytest --html=report.html
```

这将在测试会话结束时生成一个`report.html`文件。

因为图片胜过千言万语，这里有一个例子：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/pytest-qk-st-gd/img/f71502c4-fb19-427a-8299-7d04fbb01c59.png)

报告可以在 Web 服务器上进行服务以便更轻松地查看，而且它们包含了一些很好的功能，比如复选框来显示/隐藏不同类型的测试结果，还有其他插件如`pytest-selenium`甚至能够在失败的测试中附加截图，就像前面的图片一样。

它绝对值得一试。

# pytest-cpp

为了证明 pytest 框架非常灵活，`pytest-cpp`插件允许你运行用 Google Test ([`github.com/google/googletest`](https://github.com/google/googletest)) 或 Boost.Test ([`www.boost.org`](https://www.boost.org))编写的测试，这些是用 C++语言编写和运行测试的框架。

安装后，你只需要像平常一样运行 pytest：

```py
λ pytest bin/tests
```

Pytest 将找到包含测试用例的可执行文件，并自动检测它们是用`Google Test`还是`Boost.Python`编写的。它将正常运行测试并报告结果，格式整齐，熟悉 pytest 用户。

使用 pytest 运行这些测试意味着它们现在可以利用一些功能，比如使用`pytest-xdist`进行并行运行，使用`-k`进行测试选择，生成 JUnitXML 报告等等。这个插件对于使用 Python 和 C++的代码库特别有用，因为它允许你用一个命令运行所有测试，并且你可以得到一个独特的报告。

# pytest-timeout

`pytest-timeout`插件在测试达到一定超时后会自动终止测试。

你可以通过在命令行中设置全局超时来使用它：

```py
λ pytest --timeout=60
```

或者你可以使用`@pytest.mark.timeout`标记单独的测试：

```py
@pytest.mark.timeout(600)
def test_long_simulation():
   ...
```

它通过以下两种方法之一来实现超时机制：

+   `thread`：在测试设置期间，插件启动一个线程，该线程休眠指定的超时时间。如果线程醒来，它将将所有线程的回溯信息转储到`stderr`并杀死当前进程。如果测试在线程醒来之前完成，那么线程将被取消，测试继续运行。这是在所有平台上都有效的方法。

+   `signal`：在测试设置期间安排了一个`SIGALRM`，并在测试完成时取消。如果警报被触发，它将将所有线程的回溯信息转储到`stderr`并失败测试，但它将允许测试继续运行。与线程方法相比的优势是当超时发生时它不会取消整个运行，但它不支持所有平台。

该方法会根据平台自动选择，但可以在命令行或通过`@pytest.mark.timeout`的`method=`参数来进行更改。

这个插件在大型测试套件中是不可或缺的，以避免测试挂起 CI。

# pytest-annotate

Pyannotate ([`github.com/dropbox/pyannotate`](https://github.com/dropbox/pyannotate)) 是一个观察运行时类型信息并将该信息插入到源代码中的项目，而`pytest-annotate`使得在 pytest 中使用它变得很容易。

让我们回到这个简单的测试用例：

```py
def highest_rated(series):
    return sorted(series, key=itemgetter(2))[-1][0]

def test_highest_rated():
    series = [
        ("The Office", 2005, 8.8),
        ("Scrubs", 2001, 8.4),
        ("IT Crowd", 2006, 8.5),
        ("Parks and Recreation", 2009, 8.6),
        ("Seinfeld", 1989, 8.9),
    ]
    assert highest_rated(series) == "Seinfeld"
```

安装了`pytest-annotate`后，我们可以通过传递`--annotations-output`标志来生成一个注释文件：

```py
λ pytest --annotate-output=annotations.json
```

这将像往常一样运行测试套件，但它将收集类型信息以供以后使用。

之后，你可以调用`PyAnnotate`将类型信息直接应用到源代码中：

```py
λ pyannotate --type-info annotations.json -w
Refactored test_series.py
--- test_series.py (original)
+++ test_series.py (refactored)
@@ -1,11 +1,15 @@
 from operator import itemgetter
+from typing import List
+from typing import Tuple

 def highest_rated(series):
+    # type: (List[Tuple[str, int, float]]) -> str
 return sorted(series, key=itemgetter(2))[-1][0]

 def test_highest_rated():
+    # type: () -> None
 series = [
 ("The Office", 2005, 8.8),
 ("Scrubs", 2001, 8.4),
Files that were modified:
pytest-annotate.py
```

快速高效地注释大型代码库是非常整洁的，特别是如果该代码库已经有了完善的测试覆盖。

# pytest-qt

`pytest-qt`插件允许您为使用`Qt`框架（[`www.qt.io/`](https://www.qt.io/)）编写的 GUI 应用程序编写测试，支持更受欢迎的 Python 绑定集：`PyQt4`/`PyQt5`和`PySide`/`PySide2`。

它提供了一个`qtbot`装置，其中包含与 GUI 应用程序交互的方法，例如单击按钮、在字段中输入文本、等待窗口弹出等。以下是一个快速示例，展示了它的工作原理：

```py
def test_main_window(qtbot):
    widget = MainWindow()
    qtbot.addWidget(widget)

    qtbot.mouseClick(widget.about_button, QtCore.Qt.LeftButton)
    qtbot.waitUntil(widget.about_box.isVisible)
    assert widget.about_box.text() == 'This is a GUI App'
```

在这里，我们创建一个窗口，单击“关于”按钮，等待“关于”框弹出，然后确保它显示我们期望的文本。

它还包含其他好东西：

+   等待特定`Qt`信号的实用程序

+   自动捕获虚拟方法中的错误

+   自动捕获`Qt`日志消息

# pytest-randomly

测试理想情况下应该是相互独立的，确保在测试完成后进行清理，这样它们可以以任何顺序运行，而且不会以任何方式相互影响。

`pytest-randomly`通过随机排序测试，每次运行测试套件时更改它们的顺序，帮助您保持测试套件的真实性。这有助于检测测试是否具有隐藏的相互依赖性，否则您将无法发现。

它会在模块级别、类级别和函数顺序上对测试项进行洗牌。它还会在每个测试之前将`random.seed()`重置为一个固定的数字，该数字显示在测试部分的开头。可以在以后使用随机种子通过`--randomly-seed`命令行来重现失败。

作为额外的奖励，它还特别支持`factory boy`（[`factoryboy.readthedocs.io/en/latest/reference.html`](https://factoryboy.readthedocs.io/en/latest/reference.html)）、`faker`（[`pypi.python.org/pypi/faker`](https://pypi.python.org/pypi/faker)）和`numpy`（[`www.numpy.org/`](http://www.numpy.org/)）库，在每个测试之前重置它们的随机状态。

# pytest-datadir

通常，测试需要一个支持文件，例如一个包含有关喜剧系列数据的 CSV 文件，就像我们在上一章中看到的那样。`pytest-datadir`允许您将文件保存在测试旁边，并以安全的方式从测试中轻松访问它们。

假设您有这样的文件结构：

```py
tests/
    test_series.py
```

除此之外，您还有一个`series.csv`文件，需要从`test_series.py`中定义的测试中访问。

安装了`pytest-datadir`后，您只需要在相同目录中创建一个与测试文件同名的目录，并将文件放在其中：

```py
tests/
 test_series/
 series.csv
    test_series.py
```

`test_series`目录和`series.csv`应该保存到您的版本控制系统中。

现在，`test_series.py`中的测试可以使用`datadir`装置来访问文件：

```py
def test_ratings(datadir):
    with open(datadir / "series.csv", "r", newline="") as f:
        data = list(csv.reader(f))
    ...
```

`datadir`是一个指向数据目录的 Path 实例（[`docs.python.org/3/library/pathlib.html`](https://docs.python.org/3/library/pathlib.html)）。

需要注意的一点是，当我们在测试中使用`datadir`装置时，我们并不是访问原始文件的路径，而是临时副本。这确保了测试可以修改数据目录中的文件，而不会影响其他测试，因为每个测试都有自己的副本。

# pytest-regressions

通常情况下，您的应用程序或库包含产生数据集作为结果的功能。

经常测试这些结果是很繁琐且容易出错的，产生了这样的测试：

```py
def test_obtain_series_asserts():
    data = obtain_series()
    assert data[0]["name"] == "The Office"
    assert data[0]["year"] == 2005
    assert data[0]["rating"] == 8.8
    assert data[1]["name"] == "Scrubs"
    assert data[1]["year"] == 2001
    ...
```

这很快就会变得老套。此外，如果任何断言失败，那么测试就会在那一点停止，您将不知道在那一点之后是否还有其他断言失败。换句话说，您无法清楚地了解整体失败的情况。最重要的是，这也是非常难以维护的，因为如果`obtain_series()`返回的数据发生变化，您将不得不进行繁琐且容易出错的代码更新任务。

`pytest-regressions`提供了解决这类问题的装置。像前面的例子一样，一般的数据是`data_regression`装置的工作：

```py
def test_obtain_series(data_regression):
    data = obtain_series()
    data_regression.check(data)
```

第一次执行此测试时，它将失败，并显示如下消息：

```py
...
E Failed: File not found in data directory, created:
E - CH5\test_series\test_obtain_series.yml
```

它将以一个格式良好的 YAML 文件的形式将传递给`data_regression.check()`的数据转储到`test_series.py`文件的数据目录中（这要归功于我们之前看到的`pytest-datadir`装置）：

```py
- name: The Office
  rating: 8.8
  year: 2005
- name: Scrubs
  rating: 8.4
  year: 2001
- name: IT Crowd
  rating: 8.5
  year: 2006
- name: Parks and Recreation
  rating: 8.6
  year: 2009
- name: Seinfeld
  rating: 8.9
  year: 1989
```

下次运行此测试时，`data_regression`现在将传递给`data_regressions.check()`的数据与数据目录中的`test_obtain_series.yml`中找到的数据进行比较。如果它们匹配，测试通过。

然而，如果数据发生了变化，测试将失败，并显示新数据与记录数据之间的差异：

```py
E AssertionError: FILES DIFFER:
E ---
E
E +++
E
E @@ -13,3 +13,6 @@
E
E  - name: Seinfeld
E    rating: 8.9
E    year: 1989
E +- name: Rock and Morty
E +  rating: 9.3
E +  year: 2013
```

在某些情况下，这可能是一个回归，这种情况下你可以在代码中找到错误。

但在这种情况下，新数据是*正确的；*你只需要用`--force-regen`标志运行 pytest，`pytest-regressions`将为你更新数据文件的新内容：

```py
E Failed: Files differ and --force-regen set, regenerating file at:
E - CH5\test_series\test_obtain_series.yml
```

现在，如果我们再次运行测试，测试将通过，因为文件包含了新数据。

当你有数十个测试突然产生不同但正确的结果时，这将极大地节省时间。你可以通过单次 pytest 执行将它们全部更新。

我自己使用这个插件，我数不清它为我节省了多少时间。

# 值得一提的是

有太多好的插件无法放入本章。前面的示例只是一个小小的尝试，我试图在有用、有趣和展示插件架构的灵活性之间取得平衡。

以下是一些值得一提的其他插件：

+   `pytest-bdd`：pytest 的行为驱动开发

+   `pytest-benchmark`：用于对代码进行基准测试的装置。它以彩色输出输出基准测试结果

+   `pytest-csv`：将测试状态输出为 CSV 文件

+   `pytest-docker-compose`：在测试运行期间使用 Docker compose 管理 Docker 容器

+   `pytest-excel`：以 Excel 格式输出测试状态报告

+   `pytest-git`：为需要处理 git 仓库的测试提供 git 装置

+   `pytest-json`：将测试状态输出为 json 文件

+   `pytest-leaks`：通过重复运行测试并比较引用计数来检测内存泄漏

+   `pytest-menu`：允许用户从控制台菜单中选择要运行的测试

+   `pytest-mongo`：MongoDB 的进程和客户端装置

+   `pytest-mpl`：测试 Matplotlib 输出的图形的插件

+   `pytest-mysql`：MySQL 的进程和客户端装置

+   `pytest-poo`：用"pile of poo"表情符号替换失败测试的`F`字符

+   `pytest-rabbitmq`：RabbitMQ 的进程和客户端装置

+   `pytest-redis`：Redis 的进程和客户端装置

+   `pytest-repeat`：重复所有测试或特定测试多次以查找间歇性故障

+   `pytest-replay`：保存测试运行并允许用户以后执行它们，以便重现崩溃和不稳定的测试

+   `pytest-rerunfailures`：标记可以运行多次以消除不稳定测试的测试

+   `pytest-sugar`：通过添加进度条、表情符号、即时失败等来改变 pytest 控制台的外观和感觉

+   `pytest-tap`：以 TAP 格式输出测试报告

+   `pytest-travis-fold`：在 Travis CI 构建日志中折叠捕获的输出和覆盖报告

+   `pytest-vagrant`：与 vagrant boxes 一起使用的 pytest 装置

+   `pytest-vcr`：使用简单的标记自动管理`VCR.py`磁带

+   `pytest-virtualenv`：提供一个虚拟环境装置来管理测试中的虚拟环境

+   `pytest-watch`：持续监视源代码的更改并重新运行 pytest

+   `pytest-xvfb`：为 UI 测试运行`Xvfb`（虚拟帧缓冲区）

+   `tavern`：使用基于 YAML 的语法对 API 进行自动化测试

+   `xdoctest`：重写内置的 doctests 模块，使得编写和配置 doctests 更加容易

请记住，在撰写本文时，pytest 插件的数量已经超过 500 个，所以一定要浏览插件列表，以便找到自己喜欢的东西。

# 总结

在本章中，我们看到了查找和安装插件是多么容易。我们还展示了一些我每天使用并且觉得有趣的插件。我希望这让你对 pytest 的可能性有所了解，但请探索大量的插件，看看是否有任何有用的。

创建自己的插件不是本书涵盖的主题，但如果你感兴趣，这里有一些资源可以帮助你入门：

+   pytest 文档：编写插件（[`docs.pytest.org/en/latest/writing_plugins.html`](https://docs.pytest.org/en/latest/writing_plugins.html)）。

+   Brian Okken 的关于 pytest 的精彩书籍《Python 测试与 pytest》，比本书更深入地探讨了如何编写自己的插件。

在下一章中，我们将学习如何将 pytest 与现有的基于`unittest`的测试套件一起使用，包括有关如何迁移它们并逐步使用更多 pytest 功能的提示和建议。


# 第五章：将 unittest 套件转换为 pytest

在上一章中，我们已经看到了灵活的 pytest 架构如何创建了丰富的插件生态系统，拥有数百个可用的插件。我们学习了如何轻松找到和安装插件，并概述了一些有趣的插件。

现在您已经熟练掌握 pytest，您可能会遇到这样的情况，即您有一个或多个基于`unittest`的测试套件，并且希望开始使用 pytest 进行测试。在本章中，我们将讨论从简单的测试套件开始做到这一点的最佳方法，这可能需要很少或根本不需要修改，到包含多年来有机地增长的各种自定义的大型内部测试套件。本章中的大多数提示和建议都来自于我在 ESSS（[`wwww.esss.co`](https://www.esss.co)）工作时迁移我们庞大的`unittest`风格测试套件的经验。

以下是本章将涵盖的内容：

+   使用 pytest 作为测试运行器

+   使用`unittest2pytest`转换断言

+   处理设置和拆卸

+   管理测试层次结构

+   重构测试工具

+   迁移策略

# 使用 pytest 作为测试运行器

令人惊讶的是，许多人不知道的一件事是，pytest 可以直接运行`unittest`套件，无需任何修改。

例如：

```py
class Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp())
        cls.filepath = cls.temp_dir / "data.csv"
        cls.filepath.write_text(DATA.strip())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir)

    def setUp(self):
        self.grids = list(iter_grids_from_csv(self.filepath))

    def test_read_properties(self):
        self.assertEqual(self.grids[0], GridData("Main Grid", 48, 44))
        self.assertEqual(self.grids[1], GridData("2nd Grid", 24, 21))
        self.assertEqual(self.grids[2], GridData("3rd Grid", 24, 48))

    def test_invalid_path(self):
        with self.assertRaises(IOError):
            list(iter_grids_from_csv(Path("invalid file")))

    @unittest.expectedFailure
    def test_write_properties(self):
        self.fail("not implemented yet")
```

我们可以使用`unittest`运行器来运行这个：

```py
..x
----------------------------------------------------------------------
Ran 3 tests in 0.005s

OK (expected failures=1)
```

但很酷的是，pytest 也可以在不进行任何修改的情况下运行此测试：

```py
λ pytest test_simple.py
======================== test session starts ========================
...
collected 3 items

test_simple.py ..x                                             [100%]

================ 2 passed, 1 xfailed in 0.11 seconds ================
```

这使得使用 pytest 作为测试运行器变得非常容易，带来了几个好处：

+   您可以使用插件，例如`pytest-xdist`，来加速测试套件。

+   您可以使用几个命令行选项：`-k`选择测试，`--pdb`在错误时跳转到调试器，`--lf`仅运行上次失败的测试，等等。

+   您可以停止编写`self.assert*`方法，改用普通的`assert`。 pytest 将愉快地提供丰富的失败信息，即使对于基于`unittest`的子类也是如此。

为了完整起见，以下是直接支持的`unittest`习语和功能：

+   `setUp`和`tearDown`用于函数级`setup`/`teardown`

+   `setUpClass`和`tearDownClass`用于类级`setup`/`teardown`

+   `setUpModule`和`tearDownModule`用于模块级`setup`/`teardown`

+   `skip`，`skipIf`，`skipUnless`和`expectedFailure`装饰器，用于函数和类

+   `TestCase.skipTest`用于在测试内部进行命令式跳过

目前不支持以下习语：

+   `load_tests protocol`：此协议允许用户完全自定义从模块加载哪些测试（[`docs.python.org/3/library/unittest.html#load-tests-protocol`](https://docs.python.org/3/library/unittest.html#load-tests-protocol)）。 pytest 使用的集合概念与`load_tests`协议的工作方式不兼容，因此 pytest 核心团队没有计划支持此功能（如果您对细节感兴趣，请参见`#992`（[`github.com/pytest-dev/pytest/issues/992`](https://github.com/pytest-dev/pytest/issues/992)）问题）。

+   `subtests`：使用此功能的测试可以在同一测试方法内报告多个失败（[`docs.python.org/3/library/unittest.html#distinguishing-test-iterations-using-subtests`](https://docs.python.org/3/library/unittest.html#distinguishing-test-iterations-using-subtests)）。此功能类似于 pytest 自己的参数化支持，不同之处在于测试结果可以在运行时而不是在收集时确定。理论上，这可以由 pytest 支持，该功能目前正在通过问题`#1367`（[`github.com/pytest-dev/pytest/issues/1367`](https://github.com/pytest-dev/pytest/issues/1367)）进行跟踪。

**`pytest-xdist`的惊喜**

如果您决定在测试套件中使用`pytest-xdist`，请注意它会以任意顺序运行测试：每个工作进程将在完成其他测试后运行测试，因此测试执行的顺序是不可预测的。因为默认的`unittest`运行程序会按顺序顺序运行测试，并且通常以相同的顺序运行，这将经常暴露出测试套件中的并发问题，例如，试图使用相同名称创建临时目录的测试。您应该将这视为修复潜在并发问题的机会，因为它们本来就不应该是测试套件的一部分。

# unittest 子类中的 pytest 特性

尽管不是设计为在运行基于`unittest`的测试时支持所有其特性，但是支持一些 pytest 习语：

+   **普通断言**：当子类化`unittest.TestCase`时，pytest 断言内省的工作方式与之前一样

+   **标记**：标记可以正常应用于`unittest`测试方法和类。处理标记的插件在大多数情况下应该正常工作（例如`pytest-timeout`标记）

+   **自动使用**固定装置：在模块或`conftest.py`文件中定义的自动使用固定装置将在正常执行`unittest`测试方法时创建/销毁，包括在类范围的自动使用固定装置的情况下

+   **测试选择**：命令行中的`-k`和`-m`应该像正常一样工作

其他 pytest 特性与`unittest`不兼容，特别是：

+   **固定装置**：`unittest`测试方法无法请求固定装置。Pytest 使用`unittest`自己的结果收集器来执行测试，该收集器不支持向测试函数传递参数

+   **参数化**：由于与固定装置的原因相似，这也不受支持：我们需要传递参数化值，目前这是不可能的。

不依赖于固定装置的插件可能会正常工作，例如`pytest-timeout`或`pytest-randomly`。

# 使用 unitest2pytest 转换断言

一旦您将测试运行程序更改为 pytest，您就可以利用编写普通的断言语句来代替`self.assert*`方法。

转换所有的方法调用是无聊且容易出错的，这就是[`unittest2pytest`](https://github.com/pytest-dev/unittest2pytest)工具存在的原因。它将所有的`self.assert*`方法调用转换为普通的断言，并将`self.assertRaises`调用转换为适当的 pytest 习语。

使用`pip`安装它：

```py
λ pip install unittest2pytest
```

安装完成后，您现在可以在想要的文件上执行它：

```py
λ unittest2pytest test_simple2.py
RefactoringTool: Refactored test_simple2.py
--- test_simple2.py (original)
+++ test_simple2.py (refactored)
@@ -5,6 +5,7 @@
 import unittest
 from collections import namedtuple
 from pathlib import Path
+import pytest

 DATA = """
 Main Grid,48,44
@@ -49,12 +50,12 @@
 self.grids = list(iter_grids_from_csv(self.filepath))

 def test_read_properties(self):
-        self.assertEqual(self.grids[0], GridData("Main Grid", 48, 44))
-        self.assertEqual(self.grids[1], GridData("2nd Grid", 24, 21))
-        self.assertEqual(self.grids[2], GridData("3rd Grid", 24, 48))
+        assert self.grids[0] == GridData("Main Grid", 48, 44)
+        assert self.grids[1] == GridData("2nd Grid", 24, 21)
+        assert self.grids[2] == GridData("3rd Grid", 24, 48)

 def test_invalid_path(self):
-        with self.assertRaises(IOError):
+        with pytest.raises(IOError):
 list(iter_grids_from_csv(Path("invalid file")))

 @unittest.expectedFailure
RefactoringTool: Files that need to be modified:
RefactoringTool: test_simple2.py
```

默认情况下，它不会触及文件，只会显示它可以应用的更改的差异。要实际应用更改，请传递`-wn`（`--write`和`--nobackups`）。

请注意，在上一个示例中，它正确地替换了`self.assert*`调用，`self.assertRaises`，并添加了`pytest`导入。它没有更改我们测试类的子类，因为这可能会有其他后果，具体取决于您正在使用的实际子类，因此`unittest2pytest`会保持不变。

更新后的文件运行方式与以前一样：

```py
λ pytest test_simple2.py
======================== test session starts ========================
...
collected 3 items

test_simple2.py ..x                                            [100%]

================ 2 passed, 1 xfailed in 0.10 seconds ================
```

采用 pytest 作为运行程序，并能够使用普通的断言语句是一个经常被低估的巨大收获：不再需要一直输入`self.assert...`是一种解放。

在撰写本文时，`unittest2pytest`尚未处理最后一个测试中的`self.fail("not implemented yet")`语句。因此，我们需要手动用`assert 0, "not implemented yet"`替换它。也许您想提交一个 PR 来改进这个项目？([`github.com/pytest-dev/unittest2pytest`](https://github.com/pytest-dev/unittest2pytest))。

# 处理设置/拆卸

要完全将`TestCase`子类转换为 pytest 风格，我们需要用 pytest 的习语替换`unittest`。我们已经在上一节中看到了如何使用`unittest2pytest`来做到这一点。但是我们能对`setUp`和`tearDown`方法做些什么呢？

正如我们之前学到的，`TestCase`子类中的`autouse` fixtures 工作得很好，所以它们是替换`setUp`和`tearDown`方法的一种自然方式。让我们使用上一节的例子。

在转换`assert`语句之后，首先要做的是删除`unittest.TestCase`的子类化：

```py
class Test(unittest.TestCase):
    ...
```

这变成了以下内容：

```py
class Test:
    ...
```

接下来，我们需要将`setup`/`teardown`方法转换为 fixture 等效方法：

```py
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp())
        cls.filepath = cls.temp_dir / "data.csv"
        cls.filepath.write_text(DATA.strip())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir)
```

因此，类作用域的`setUpClass`和`tearDownClass`方法将成为一个单一的类作用域 fixture：

```py
    @classmethod
    @pytest.fixture(scope='class', autouse=True)
    def _setup_class(cls):
        temp_dir = Path(tempfile.mkdtemp())
        cls.filepath = temp_dir / "data.csv"
        cls.filepath.write_text(DATA.strip())
        yield
        shutil.rmtree(temp_dir)
```

由于`yield`语句，我们可以很容易地在 fixture 本身中编写拆卸代码，就像我们已经学到的那样。

以下是一些观察：

+   Pytest 不在乎我们如何称呼我们的 fixture，所以我们可以继续使用旧的`setUpClass`名称。我们选择将其更改为`setup_class`，有两个目标：避免混淆这段代码的读者，因为它可能看起来仍然是一个`TestCase`子类，并且使用`_`前缀表示这个 fixture 不应该像普通的 pytest fixture 一样使用。

+   我们将`temp_dir`更改为局部变量，因为我们不再需要在`cls`中保留它。以前，我们不得不这样做，因为我们需要在`tearDownClass`期间访问`cls.temp_dir`，但现在我们可以将其保留为一个局部变量，并在`yield`语句之后访问它。这是使用`yield`将设置和拆卸代码分开的美妙之一：你不需要保留上下文变量；它们自然地作为函数的局部变量保留。

我们使用相同的方法来处理`setUp`方法：

```py
    def setUp(self):
        self.grids = list(iter_grids_from_csv(self.filepath))
```

这变成了以下内容：

```py
    @pytest.fixture(autouse=True)
    def _setup(self):
        self.grids = list(iter_grids_from_csv(self.filepath))
```

这种技术非常有用，因为你可以通过一组最小的更改得到一个纯粹的 pytest 类。此外，像我们之前做的那样为 fixtures 使用命名约定，有助于向读者传达 fixtures 正在转换旧的`setup`/`teardown`习惯。

现在这个类是一个合适的 pytest 类，你可以自由地使用 fixtures 和参数化。

# 管理测试层次结构

正如我们所看到的，在大型测试套件中需要共享功能是很常见的。由于`unittest`是基于子类化`TestCase`，所以在`TestCase`子类本身中放置额外的功能是很常见的。例如，如果我们需要测试需要数据库的应用逻辑，我们可能最初会直接在我们的`TestCase`子类中添加启动和连接到数据库的功能：

```py
class Test(unittest.TestCase):

    def setUp(self):
        self.db_file = self.create_temporary_db()
        self.session = self.connect_db(self.db_file)

    def tearDown(self):
        self.session.close()
        os.remove(self.db_file)

    def create_temporary_db(self):
        ...

    def connect_db(self, db_file):
        ...

    def create_table(self, table_name, **fields):
        ...

    def check_row(self, table_name, **query):
        ...

    def test1(self):
        self.create_table("weapons", name=str, type=str, dmg=int)
        ...
```

这对于单个测试模块效果很好，但通常情况下，我们需要在以后的某个时候在另一个测试模块中使用这个功能。`unittest`模块没有内置的功能来共享常见的`setup`/`teardown`代码，所以大多数人自然而然地会将所需的功能提取到一个超类中，然后在需要的地方从中创建一个子类：

```py
# content of testing.py
class DataBaseTesting(unittest.TestCase):

    def setUp(self):
        self.db_file = self.create_temporary_db()
        self.session = self.connect_db(self.db_file)

    def tearDown(self):
        self.session.close()
        os.remove(self.db_file)

    def create_temporary_db(self):
        ...

    def connect_db(self, db_file):
        ...

    def create_table(self, table_name, **fields):
        ...

    def check_row(self, table_name, **query):
        ...

# content of test_database2.py
from . import testing

class Test(testing.DataBaseTesting):

    def test1(self):
        self.create_table("weapons", name=str, type=str, dmg=int)
        ...

```

超类通常不仅包含`setup`/`teardown`代码，而且通常还包括调用`self.assert*`执行常见检查的实用函数（例如在上一个例子中的`check_row`）。

继续我们的例子：一段时间后，我们需要在另一个测试模块中完全不同的功能，例如，测试一个 GUI 应用程序。我们现在更加明智，怀疑我们将需要在几个其他测试模块中使用 GUI 相关的功能，所以我们首先创建一个具有我们直接需要的功能的超类：

```py
class GUITesting(unittest.TestCase):

    def setUp(self):
        self.app = self.create_app()

    def tearDown(self):
        self.app.close_all_windows()

    def mouse_click(self, window, button):
        ...

    def enter_text(self, window, text):
        ...
```

将`setup`/`teardown`和测试功能移动到超类的方法是可以的，并且易于理解。

当我们需要在同一个测试模块中使用两个不相关的功能时，问题就出现了。在这种情况下，我们别无选择，只能求助于多重继承。假设我们需要测试连接到数据库的对话框；我们将需要编写这样的代码：

```py
from . import testing

class Test(testing.DataBaseTesting, testing.GUITesting):

    def setUp(self):
 testing.DataBaseTesting.setUp(self)
 testing.GUITesting.setUp(self)

    def tearDown(self):
 testing.GUITesting.setUp(self)
 testing.DataBaseTesting.setUp(self)
```

一般来说，多重继承会使代码变得不太可读，更难以理解。在这里，它还有一个额外的恼人之处，就是我们需要显式地按正确的顺序调用`setUp`和`tearDown`。

还要注意的一点是，在 `unittest` 框架中，`setUp` 和 `tearDown` 是可选的，因此如果某个类不需要任何拆卸代码，通常不会声明 `tearDown` 方法。如果此类包含的功能后来移动到超类中，许多子类可能也不会声明 `tearDown` 方法。问题出现在后来的多重继承场景中，当您改进超类并需要添加 `tearDown` 方法时，因为现在您必须检查所有子类，并确保它们调用超类的 `tearDown` 方法。

因此，假设我们发现自己处于前述情况，并且希望开始使用与 `TestCase` 测试不兼容的 pytest 功能。我们如何重构我们的实用类，以便我们可以自然地从 pytest 中使用它们，并且保持现有的基于 `unittest` 的测试正常工作？

# 使用 fixtures 重用测试代码

我们应该做的第一件事是将所需的功能提取到定义良好的 fixtures 中，并将它们放入 `conftest.py` 文件中。继续我们的例子，我们可以创建 `db_testing` 和 `gui_testing` fixtures：

```py
class DataBaseFixture:

    def __init__(self):
        self.db_file = self.create_temporary_db()
        self.session = self.connect_db(self.db_file)

    def teardown(self):
        self.session.close()
        os.remove(self.db_file)

    def create_temporary_db(self):
        ...

    def connect_db(self, db_file):
        ...

    ...

@pytest.fixture
def db_testing():
    fixture = DataBaseFixture()
    yield fixture
    fixture.teardown()

class GUIFixture:

    def __init__(self):
        self.app = self.create_app()

    def teardown(self):
        self.app.close_all_windows()

    def mouse_click(self, window, button):
        ...

    def enter_text(self, window, text):
        ...

@pytest.fixture
def gui_testing():
    fixture = GUIFixture()
    yield fixture
    fixture.teardown()
```

现在，您可以开始使用纯 pytest 风格编写新的测试，并使用 `db_testing` 和 `gui_testing` fixtures，这很棒，因为它为在新测试中使用 pytest 功能打开了大门。但这里很酷的一点是，我们现在可以更改 `DataBaseTesting` 和 `GUITesting` 来重用 fixtures 提供的功能，而不会破坏现有代码：

```py
class DataBaseTesting(unittest.TestCase):

    @pytest.fixture(autouse=True)
    def _setup(self, db_testing):
 self._db_testing = db_testing

    def create_temporary_db(self):
        return self._db_testing.create_temporary_db()

    def connect_db(self, db_file):
        return self._db_testing.connect_db(db_file)

    ...

class GUITesting(unittest.TestCase):

    @pytest.fixture(autouse=True)
 def _setup(self, gui_testing):
 self._gui_testing = gui_testing

    def mouse_click(self, window, button):
        return self._gui_testing.mouse_click(window, button)

    ...
```

我们的 `DatabaseTesting` 和 `GUITesting` 类通过声明一个自动使用的 `_setup` fixture 来获取 fixture 值，这是我们在本章早期学到的一个技巧。我们可以摆脱 `tearDown` 方法，因为 fixture 将在每次测试后自行清理，而实用方法变成了在 fixture 中实现的方法的简单代理。

作为奖励分，`GUIFixture` 和 `DataBaseFixture` 也可以使用其他 pytest fixtures。例如，我们可能可以移除 `DataBaseTesting.create_temporary_db()`，并使用内置的 `tmpdir` fixture 为我们创建临时数据库文件：

```py
class DataBaseFixture:

    def __init__(self, tmpdir):
        self.db_file = str(tmpdir / "file.db")
        self.session = self.connect_db(self.db_file)

    def teardown(self):
        self.session.close()

    ...

@pytest.fixture
def db_testing(tmpdir):
    fixture = DataBaseFixture(tmpdir)
    yield fixture
    fixture.teardown()
```

然后使用其他 fixtures 可以极大地简化现有的测试实用程序代码。

值得强调的是，这种重构不需要对现有测试进行任何更改。这里，fixtures 的一个好处再次显而易见：fixture 的要求变化不会影响使用 fixture 的测试。

# 重构测试实用程序

在前一节中，我们看到测试套件可能使用子类来共享测试功能，并且如何将它们重构为 fixtures，同时保持现有的测试正常工作。

在 `unittest` 套件中通过超类共享测试功能的另一种选择是编写单独的实用类，并在测试中使用它们。回到我们的例子，我们需要具有与数据库相关的设施，这是一种在 `unittest` 友好的方式实现的方法，而不使用超类：

```py
# content of testing.py
class DataBaseTesting:

    def __init__(self, test_case):        
        self.db_file = self.create_temporary_db()
        self.session = self.connect_db(self.db_file)
        self.test_case = test_case
        test_case.addCleanup(self.teardown)

    def teardown(self):
        self.session.close()
        os.remove(self.db_file)

    ...

    def check_row(self, table_name, **query):
        row = self.session.find(table_name, **query)
        self.test_case.assertIsNotNone(row)
        ...

# content of test_1.py
from testing import DataBaseTesting

class Test(unittest.TestCase):

    def test_1(self):
        db_testing = DataBaseTesting(self)
        db_testing.create_table("weapons", name=str, type=str, dmg=int)
        db_testing.check_row("weapons", name="zweihander")
        ...

```

在这种方法中，我们将测试功能分离到一个类中，该类将当前的 `TestCase` 实例作为第一个参数，然后是任何其他所需的参数。

`TestCase`实例有两个目的：为类提供对各种`self.assert*`函数的访问，并作为一种方式向`TestCase.addCleanup`注册清理函数（[`docs.python.org/3/library/unittest.html#unittest.TestCase.addCleanup`](https://docs.python.org/3/library/unittest.html#unittest.TestCase.addCleanup)）。`TestCase.addCleanup`注册的函数将在每个测试完成后调用，无论它们是否成功。我认为它们是`setUp`/`tearDown`函数的一个更好的替代方案，因为它们允许资源被创建并立即注册进行清理。在`setUp`期间创建所有资源并在`tearDown`期间释放它们的缺点是，如果在`setUp`方法中引发任何异常，那么`tearDown`将根本不会被调用，从而泄漏资源和状态，这可能会影响后续的测试。

如果您的`unittest`套件使用这种方法进行测试设施，那么好消息是，您可以轻松地转换/重用这些功能以供 pytest 使用。

因为这种方法与 fixtures 的工作方式非常相似，所以很容易稍微改变类以使其作为 fixtures 工作：

```py
# content of testing.py
class DataBaseFixture:

    def __init__(self):
        self.db_file = self.create_temporary_db()
        self.session = self.connect_db(self.db_file)

    ...

    def check_row(self, table_name, **query):
        row = self.session.find(table_name, **query)
        assert row is not None

# content of conftest.py
@pytest.fixture
def db_testing():
    from .testing import DataBaseFixture
    result = DataBaseFixture()
    yield result
    result.teardown()
```

我们摆脱了对`TestCase`实例的依赖，因为我们的 fixture 现在负责调用`teardown()`，并且我们可以自由地使用普通的 asserts 而不是`Test.assert*`方法。

为了保持现有的套件正常工作，我们只需要创建一个薄的子类来处理在与`TestCase`子类一起使用时的清理：

```py
# content of testing.py
class DataBaseTesting(DataBaseFixture):

    def __init__(self, test_case):
        super().__init__()
        test_case.addCleanup(self.teardown) 
```

通过这种小的重构，我们现在可以在新测试中使用原生的 pytest fixtures，同时保持现有的测试与以前完全相同的工作方式。

虽然这种方法效果很好，但一个问题是，不幸的是，我们无法在`DataBaseFixture`类中使用其他 pytest fixtures（例如`tmpdir`），而不破坏在`TestCase`子类中使用`DataBaseTesting`的兼容性。

# 迁移策略

能够立即使用 pytest 作为运行器开始使用`unittest`-based 测试绝对是一个非常强大的功能。

最终，您需要决定如何处理现有的基于`unittest`的测试。您可以选择几种方法：

+   **转换所有内容**：如果您的测试套件相对较小，您可能决定一次性转换所有测试。这样做的好处是，您不必妥协以保持现有的`unittest`套件正常工作，并且更容易被他人审查，因为您的拉取请求将具有单一主题。

+   **边转换边进行**：您可能决定根据需要转换测试和功能。当您需要添加新测试或更改现有测试时，您可以利用这个机会转换测试和/或重构功能，使用前几节中的技术来创建 fixtures。如果您不想花时间一次性转换所有内容，而是慢慢地铺平道路，使 pytest 成为唯一的测试套件，那么这是一个很好的方法。

+   **仅新测试**：您可能决定永远不触及现有的`unittest`套件，只在 pytest 风格中编写新测试。如果您有成千上万的测试，可能永远不需要进行维护，那么这种方法是合理的，但您将不得不保持前几节中展示的混合方法永远正常工作。

根据您的时间预算和测试套件的大小选择要使用的迁移策略。

# 总结

我们已经讨论了一些关于如何在各种规模的基于`unittest`的测试套件中使用 pytest 的策略和技巧。我们从讨论如何使用 pytest 作为测试运行器开始，以及哪些功能适用于`TestCase`测试。我们看了看如何使用`unittest2pytest`工具将`self.assert*`方法转换为普通的 assert 语句，并充分利用 pytest 的内省功能。然后，我们学习了一些关于如何将基于`unittest`的`setUp`/`tearDown`代码迁移到 pytest 风格的测试类中的技巧，管理在测试层次结构中分散的功能，以及一般的实用工具。最后，我们总结了可能的迁移策略概述，适用于各种规模的测试套件。

在下一章中，我们将简要总结本书学到的内容，并讨论接下来可能会有什么。
