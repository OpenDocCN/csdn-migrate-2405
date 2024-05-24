# C#9 和 .NET5 软件架构（三）

> 原文：[`zh.annas-archive.org/md5/83D8F5A1D11ACA866E980121BEEF9AAA`](https://zh.annas-archive.org/md5/83D8F5A1D11ACA866E980121BEEF9AAA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：在 C#中与数据交互-Entity Framework Core

正如我们在*第五章*中提到的，*将微服务架构应用于企业应用程序*，软件系统被组织成层，每一层通过接口与前后层通信，这些接口不依赖于层的实现方式。当软件是一个商业/企业系统时，通常至少包含三层：数据层、业务层和表示层。一般来说，每一层提供的接口以及层的实现方式取决于应用程序。

然而，事实证明，数据层提供的功能非常标准，因为它们只是将数据从数据存储子系统映射到对象，反之亦然。这导致了以一种实质性的声明方式实现数据层的通用框架的构想。这些工具被称为**对象关系映射**（**ORM**）工具，因为它们是基于关系数据库的数据存储子系统。然而，它们也可以很好地与现代的非关系存储（如 MongoDB 和 Azure Cosmos DB）一起使用，因为它们的数据模型更接近目标对象模型，而不是纯粹的关系模型。

在本章中，我们将涵盖以下主题：

+   理解 ORM 基础知识

+   配置 Entity Framework Core

+   Entity Framework Core 迁移

+   使用 Entity Framework Core 查询和更新数据

+   部署您的数据层

+   理解 Entity Framework Core 高级功能-全局过滤器

本章描述了 ORM 以及如何配置它们，然后重点介绍了 Entity Framework Core，这是.NET 5 中包含的 ORM。

# 技术要求

本章需要免费的 Visual Studio 2019 社区版或更高版本，并安装了所有数据库工具。

本章中的所有概念都将通过基于 WWTravelClub 书籍用例的实际示例进行澄清。您可以在[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5`](https://github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5)找到本章的代码。

# 理解 ORM 基础知识

ORM 将关系数据库表映射为内存中的对象集合，其中对象属性对应于数据库表字段。来自 C#的类型，如布尔值、数字类型和字符串，都有对应的数据库类型。如果映射的数据库中没有 GUID，则诸如 GUID 之类的类型将映射到它们的等效字符串表示。所有日期和时间类型都映射到 C#的`DateTime`，当日期/时间不包含时区信息时，或者映射到`DateTimeOffset`，当日期/时间还包含显式时区信息时。任何数据库时间持续时间都映射到`TimeSpan`。最后，单个字符根本不应该映射到数据库字段。

由于大多数面向对象语言的字符串属性没有与之关联的长度限制（而数据库字符串字段通常有长度限制），因此在数据库映射配置中考虑了数据库限制。一般来说，当需要指定数据库类型和面向对象语言类型之间的映射时，这些选项都在映射配置中声明。

整个配置的定义方式取决于具体的 ORM。Entity Framework Core 提供了三种选项：

+   数据注释（属性注释）

+   名称约定

+   基于配置对象和方法的流畅配置接口

虽然流畅接口可以用于指定任何配置选项，但数据注释和名称约定只能用于其中的一小部分。

就个人而言，我更喜欢对大多数设置使用流畅的接口。我仅在指定具有 ID 属性名称的主键时使用名称约定，因为我发现仅依赖名称约定进行更复杂的设置也是非常危险的。实际上，名称约定上没有编译时检查，因此重新工程操作可能会错误地更改或破坏一些 ORM 设置。

我主要使用数据注释来指定属性可能值的约束，例如值的最大长度，或者属性是必填的且不能为空。实际上，这些约束限制了每个属性中指定的类型，因此将它们放在应用的属性旁边可以增加代码的可读性。

为了增加代码的可读性和可维护性，所有其他设置最好通过使用流畅的接口进行分组和组织。

每个 ORM 都适应于特定的 DB 类型（Oracle、MySQL、SQL Server 等），具有称为**提供程序**或**连接器**的特定于 DB 的适配器。Entity Framework Core 具有大多数可用 DB 引擎的提供程序。

可以在[`docs.microsoft.com/en-US/ef/core/providers/`](https://docs.microsoft.com/en-US/ef/core/providers/)找到完整的提供程序列表。

适配器对于 DB 类型的差异、事务处理方式以及 SQL 语言未标准化的所有其他特性都是必需的。

表之间的关系用对象指针表示。例如，在一对多关系中，映射到关系*一*方的类包含一个集合，该集合由关系*多*方上的相关对象填充。另一方面，映射到关系*多*方的类具有一个简单的属性，该属性由关系*一*方上的唯一相关对象填充。

整个数据库（或其中的一部分）由一个内存缓存类表示，该类包含映射到 DB 表的每个集合的属性。首先，在内存缓存类的实例上执行查询和更新操作，然后将此实例与数据库同步。

Entity Framework Core 使用的内存缓存类称为`DbContext`，它还包含映射配置。更具体地说，通过继承`DbContext`并将其添加到所有映射集合和所有必要的配置信息中，可以获得特定于应用程序的内存缓存类。

总之，`DbContext`子类实例包含与数据库同步以获取/更新实际数据的 DB 的部分快照。

使用在内存缓存类的集合上进行方法调用的查询语言执行 DB 查询。实际的 SQL 是在同步阶段创建和执行的。例如，Entity Framework Core 在映射到 DB 表的集合上执行**语言集成查询**（**LINQ**）。

一般来说，LINQ 查询会产生`IEnumerable`实例，也就是说，在查询结束时创建`IEnumerable`时，集合的元素并不会被计算，而是当您尝试从`IEnumerable`中实际检索集合元素时才会计算。这称为延迟评估或延迟执行。它的工作方式如下：

+   从`DbContext`的映射集合开始的 LINQ 查询会创建`IQueryable`的特定子类型。

+   `IQueryable`包含发出对数据库查询所需的所有信息，但是当检索到`IQueryable`的第一个元素时，实际的 SQL 才会被生成和执行。

+   通常，每个 Entity Framework 查询都以`ToList`或`ToArray`操作结束，将`IQueryable`转换为列表或数组，从而导致在数据库上实际执行查询。

+   如果查询预计只返回单个元素或根本没有元素，通常我们会执行一个`SingleOrDefault`操作，该操作返回一个元素（如果有的话）或`null`。

此外，通过在表示数据库表的`DbContext`集合属性上模拟这些操作，也可以对 DB 表执行更新、删除和添加新实体。但是，只有在通过查询加载到内存集合中后，才能以这种方式更新或删除实体。更新查询需要根据需要修改实体的内存表示，而删除查询需要从其内存映射集合中删除实体的内存表示。在 Entity Framework Core 中，通过调用集合的`Remove(entity)`方法执行删除操作。

添加新实体没有进一步的要求。只需将新实体添加到内存集合中即可。对各种内存集合进行的更新、删除和添加实际上是通过显式调用 DB 同步方法传递到数据库的。

例如，当您调用`DbContext.SaveChanges()`方法时，Entity Framework Core 会将在`DbContext`实例上执行的所有更改传递到数据库。

在同步操作期间传递到数据库的更改是在单个事务中执行的。此外，对于具有事务的显式表示的 ORM（如 Entity Framework Core），同步操作是在事务范围内执行的，因为它使用该事务而不是创建新事务。

本章的其余部分将解释如何使用 Entity Framework Core，以及基于本书的 WWTravelClub 用例的一些示例代码。

# 配置 Entity Framework Core

由于数据库处理被限制在专用应用程序层中，因此最好的做法是在一个单独的库中定义您的 Entity Framework Core（`DbContext`）。因此，我们需要定义一个.NET Core 类库项目。正如我们在*第二章*的*书籍用例-理解.NET Core 项目的主要类型*部分中讨论的那样，我们有两种不同类型的库项目：**.NET Standard**和**.NET (Core)**。

虽然.NET Core 库与特定的.NET Core 版本相关联，但.NET Standard 2.0 库具有广泛的应用范围，因为它们可以与大于 2.0 的任何.NET 版本以及经典的.NET Framework 4.7.2 及以上版本一起使用。

然而，`Microsoft.EntityFrameworkCore`包的第 5 版，也就是随.NET 5 一起发布的版本，仅依赖于.NET Standard 2.1。这意味着它不是设计用于特定的.NET（Core）版本，而是只需要支持.NET Standard 2.1 的.NET Core 版本。因此，Entity Framework 5 可以与.NET 5 以及高于或等于 2.1 的任何.NET Core 版本正常工作。

由于我们的库不是通用库（它只是特定.NET 5 应用程序的一个组件），所以我们可以选择.NET 5 库而不是选择.NET Standard 库项目。我们的.NET 5 库项目可以按以下方式创建和准备：

1.  打开 Visual Studio 并定义一个名为`WWTravelClubDB`的新解决方案，然后选择可用的最新.NET Core 版本的**类库（.NET Core）**。

1.  我们必须安装所有与 Entity Framework Core 相关的依赖项。安装所有必要的依赖项的最简单方法是添加我们将要使用的数据库引擎提供程序的 NuGet 包 - 在我们的情况下是 SQL Server - 正如我们在*第四章*，*决定最佳基于云的解决方案*中提到的。实际上，任何提供程序都将安装所有所需的包，因为它们都作为依赖项。因此，让我们添加最新稳定版本的`Microsoft.EntityFrameworkCore.SqlServer`。如果您计划使用多个数据库引擎，还可以添加其他提供程序，因为它们可以并存。在本章的后面，我们将安装其他包含我们需要处理 Entity Framework Core 的工具的 NuGet 包。然后，我们将解释如何安装进一步需要处理 Entity Framework Core 配置的工具。

1.  让我们将默认的`Class1`类重命名为`MainDbContext`。这是自动添加到类库中的。

1.  现在，让我们用以下代码替换其内容：

```cs
using System;
using Microsoft.EntityFrameworkCore;
namespace WWTravelClubDB
{
    public class MainDbContext: DbContext
    {
        public MainDbContext(DbContextOptions options)
            : base(options)
        {
        }
        protected override void OnModelCreating(ModelBuilder 
        builder)
        {
        } 
    }
} 
```

1.  我们继承自`DbContext`，并且需要将`DbContextOptions`传递给`DbContext`构造函数。`DbContextOptions`包含创建选项，如数据库连接字符串，这取决于目标数据库引擎。

1.  所有映射到数据库表的集合将作为`MainDbContext`的属性添加。映射配置将在重写的`OnModelCreating`方法中使用传递的`ModelBuilder`对象来定义。

下一步是创建表示所有数据库表行的所有类。这些称为**实体**。我们需要为要映射的每个数据库表创建一个实体类。让我们在项目根目录下创建一个`Models`文件夹。下一小节将解释如何定义所有所需的实体。

## 定义数据库实体

数据库设计，就像整个应用程序设计一样，是按迭代进行的。假设在第一次迭代中，我们需要一个包含两个数据库表的原型：一个用于所有旅行套餐，另一个用于所有套餐引用的位置。每个套餐只涵盖一个位置，而单个位置可能被多个套餐涵盖，因此这两个表通过一对多的关系相连。

因此，让我们从位置数据库表开始。正如我们在上一节末尾提到的，我们需要一个实体类来表示这个表的行。让我们称实体类为`Destination`：

```cs
namespace WWTravelClubDB.Models
{
    public class Destination
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Country { get; set; }
        public string Description { get; set; }
    }
} 
```

所有数据库字段必须由可读/写的 C#属性表示。假设每个目的地都类似于一个城镇或地区，可以通过其名称和所在国家来定义，并且所有相关信息都包含在其`Description`中。在将来的迭代中，我们可能会添加几个字段。`Id`是自动生成的键。

然而，现在，我们需要添加关于如何将所有字段映射到数据库字段的信息。在 Entity Framework Core 中，所有基本类型都会自动映射到数据库类型，由所使用的数据库引擎特定提供程序（在我们的情况下是 SQL Server 提供程序）。

我们唯一的担忧是：

+   字符串的长度限制：可以通过为每个字符串属性应用适当的`MaxLength`和`MinLength`属性来考虑。所有对实体配置有用的属性都包含在`System.ComponentModel.DataAnnotations`和`System.ComponentModel.DataAnnotations.Schema`命名空间中。因此，最好将它们都添加到所有实体定义中。

+   **指定哪些字段是必填的，哪些是可选的**：如果项目没有使用新的可空引用类型功能，默认情况下，所有引用类型（例如所有字符串）都被假定为可选的，而所有值类型（例如数字和 GUID）都被假定为必填的。如果我们希望引用类型是必填的，那么我们必须用`Required`属性进行修饰。另一方面，如果我们希望`T`类型的属性是可选的，并且`T`是值类型或者可空引用类型功能已经开启，那么我们必须用`T?`替换`T`。

+   **指定哪个属性代表主键**：可以通过用`Key`属性修饰属性来指定主键。然而，如果没有找到`Key`属性，那么名为`Id`的属性（如果有的话）将被视为主键。在我们的情况下，不需要`Key`属性。

由于每个目的地都在一对多关系的*一*侧，它必须包含一个与相关包实体相关的集合；否则，我们将无法在 LINQ 查询的子句中引用相关实体。

将所有内容放在一起，`Destination`类的最终版本如下：

```cs
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace WWTravelClubDB.Models
{
    public class Destination
    {
        public int Id { get; set; }
        [MaxLength(128), Required]
        public string Name { get; set; }
        [MaxLength(128), Required]
        public string Country { get; set; }
        public string Description { get; set; }
        public ICollection<Package> Packages { get; set; }
    }
} 
```

由于`Description`属性没有长度限制，它将以 SQL Server `nvarchar(MAX)`字段的无限长度实现。我们可以以类似的方式编写`Package`类的代码：

```cs
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace WWTravelClubDB.Models
{
    public class Package
    {
        public int Id { get; set; }
        [MaxLength(128), Required]
        public string Name { get; set; }
        [MaxLength(128)]
        public string Description { get; set; }
        public decimal Price { get; set; }
        public int DurationInDays { get; set; }
        public DateTime? StartValidityDate { get; set; }
        public DateTime? EndValidityDate { get; set; }
        public Destination MyDestination { get; set; }
        public int DestinationId { get; set; }
    }
} 
```

每个包都有一个持续时间（以天为单位），以及可选的开始和结束日期，其中包的优惠有效。`MyDestination`将包与它们与`Destination`实体的多对一关系连接起来，而`DestinationId`是同一关系的外键。

虽然不是必须指定外键，但这是一个好习惯，因为这是唯一指定关系的一些属性的方法。例如，在我们的情况下，由于`DestinationId`是一个`int`（值类型），它是必填的。因此，这里的关系是一对多，而不是（0,1）-对多。将`DestinationId`定义为`int?`，而不是`int`，会将一对多关系转变为（0,1）-对多关系。此外，正如我们将在本章后面看到的那样，有一个外键的显式表示大大简化了更新操作和一些查询。

在下一节中，我们将解释如何定义表示数据库表的内存集合。

## 定义映射集合

一旦我们定义了所有的实体，它们就是数据库行的面向对象表示，我们需要定义表示数据库表本身的内存集合。正如我们在*理解 ORM 基础*部分中提到的，所有数据库操作都映射到这些集合上的操作（本章的*使用 Entity Framework Core 查询和更新数据*部分将解释如何）。对于每个实体`T`，只需在我们的`DbContext`中添加一个`DbSet<T>`集合属性即可。通常，每个属性的名称是通过将实体名称变为复数形式得到的。因此，我们需要将以下两个属性添加到我们的`MainDbContext`中：

```cs
public DbSet<Package> Packages { get; set; }
public DbSet<Destination> Destinations { get; set; } 
```

到目前为止，我们已经将数据库内容翻译成属性、类和数据注释。然而，Entity Framework 需要更多信息来与数据库交互。下一小节将解释如何提供这些信息。

## 完成映射配置

我们无法在实体定义中指定的映射配置信息必须在`OnModelCreating DbContext`方法中添加。每个与实体`T`相关的配置信息都以`builder.Entity<T>()`开头，并继续调用指定该约束类型的方法。进一步嵌套调用指定约束的更多属性。例如，我们的一对多关系可以配置如下：

```cs
builder.Entity<Destination>()
    .HasMany(m => m.Packages)
    .WithOne(m => m.MyDestination)
    .HasForeignKey(m => m.DestinationId)
    .OnDelete(DeleteBehavior.Cascade); 
```

关系的两侧是通过我们添加到实体的导航属性来指定的。`HasForeignKey`指定外部键。最后，`OnDelete`指定了在删除目标时要执行的操作。在我们的情况下，它执行了与该目的地相关的所有包的级联删除。

可以通过从关系的另一侧开始定义相同的配置，也就是从`builder.Entity<Package>()`开始：

```cs
builder.Entity<Package>()
    .HasOne(m => m.MyDestination)
    .WithMany(m => m.Packages)
    .HasForeignKey(m => m.DestinationId)
    .OnDelete(DeleteBehavior.Cascade); 
```

唯一的区别是前面语句的`HasMany-WithOne`方法被`HasOne-WithMany`方法替换，因为我们是从关系的另一侧开始的。在这里，我们还可以选择每个小数属性在其映射的数据库字段中表示的精度。默认情况下，小数由 18 位和 2 位小数表示。您可以使用类似以下内容为每个属性更改此设置：

```cs
...
.Property(m => m.Price)
        .HasPrecision(10, 3); 
```

`ModelBuilder builder`对象允许我们使用以下内容指定数据库索引：

```cs
builder.Entity<T>()
   .HasIndex(m => m.PropertyName); 
```

多属性索引定义如下：

```cs
builder.Entity<T>()
    .HasIndex("propertyName1", "propertyName2", ...); 
```

从版本 5 开始，索引也可以通过应用于类的属性来定义。以下是单属性索引的情况：

```cs
[Index(nameof(Property), IsUnique = true)]
public class MyClass
{
    public int Id { get; set; }
    [MaxLength(128)]
    public string Property { get; set; }
} 
```

以下是多属性索引的情况：

```cs
[Index(nameof(Property1), nameof(Property2), IsUnique = false)]
public class MyComplexIndexClass
{
    public int Id { get; set; }
    [MaxLength(64)]
    public string Property1 { get; set; }
    [MaxLength(64)]
    public string Property2 { get; set; }
} 
```

如果我们添加了所有必要的配置信息，那么我们的`OnModelCreating`方法将如下所示：

```cs
protected override void OnModelCreating(ModelBuilder builder)
{
    builder.Entity<Destination>()
        .HasMany(m => m.Packages)
        .WithOne(m => m.MyDestination)
        .HasForeignKey(m => m.DestinationId)
        .OnDelete(DeleteBehavior.Cascade);
    builder.Entity<Destination>()
        .HasIndex(m => m.Country);
    builder.Entity<Destination>()
        .HasIndex(m => m.Name);
    builder.Entity<Package>()
        .HasIndex(m => m.Name);
    builder.Entity<Package>()
        .HasIndex(nameof(Package.StartValidityDate),
                  nameof(Package.EndValidityDate));
} 
```

前面的示例展示了一对多关系，但 Entity Framework Core 5 也支持多对多关系：

```cs
 modelBuilder
        .Entity<Teacher>()
        .HasMany(e => e.Classrooms)
        .WithMany(e => e.Teachers) 
```

在前面的情况下，联接实体和数据库联接表是自动创建的，但您也可以指定现有实体作为联接实体。在前面的示例中，联接实体可能是老师在每个教室教授的课程：

```cs
modelBuilder
  Entity<Teacher>()
  .HasMany(e => e.Classrooms)
  .WithMany(e => e.Teachers)
      .UsingEntity<Course>(
           b => b.HasOne(e => e.Teacher).WithMany()
           .HasForeignKey(e => e.TeacherId),
           b => b.HasOne(e => e.Classroom).WithMany()
           .HasForeignKey(e => e.ClassroomId)); 
```

一旦配置了 Entity Framework Core，我们可以使用所有配置信息来创建实际的数据库，并在应用程序发展过程中放置所有需要的工具，以便更新数据库的结构。下一节将解释如何进行。

# Entity Framework Core 迁移

现在我们已经配置了 Entity Framework 并定义了特定于应用程序的`DbContext`子类，我们可以使用 Entity Framework Core 设计工具来生成物理数据库，并创建 Entity Framework Core 与数据库交互所需的数据库结构快照。

每个需要它们的项目中必须安装 Entity Framework Core 设计工具作为 NuGet 包。有两个等效的选项：

+   **适用于任何 Windows 控制台的工具**：这些工具通过`Microsoft.EntityFrameworkCore.Design` NuGet 包提供。所有 Entity Framework Core 命令都以`dotnet ef .....`格式，因为它们包含在`ef`命令行的.NET Core 应用程序中。

+   **专门用于 Visual Studio Package Manager 控制台的工具**：这些工具包含在`Microsoft.EntityFrameworkCore.Tools` NuGet 包中。它们不需要`dotnet ef`前缀，因为它们只能从 Visual Studio 内的**Package Manager Console**中启动。

Entity Framework Core 的设计工具在设计/更新过程中使用。该过程如下：

1.  根据需要修改`DbContext`和实体的定义。

1.  我们启动设计工具，要求 Entity Framework Core 检测和处理我们所做的所有更改。

1.  一旦启动，设计工具将更新数据库结构快照并生成一个新的*迁移*，即一个包含我们需要的所有指令的文件，以便修改物理数据库以反映我们所做的所有更改。

1.  我们启动另一个工具来使用新创建的迁移更新数据库。

1.  我们测试新配置的 DB 层，如果需要新的更改，我们回到*步骤 1*。

1.  当数据层准备就绪时，它被部署到暂存或生产环境中，所有迁移再次应用到实际的暂存/生产数据库。

这在各种软件项目迭代和应用程序的生命周期中会重复多次。

如果我们操作的是已经存在的数据库，我们需要配置`DbContext`及其模型，以反映我们想要映射的所有表的现有结构。然后，如果我们想要开始使用迁移而不是继续进行直接的数据库更改，我们可以调用设计工具，并使用`IgnoreChanges`选项，以便它们生成一个空迁移。此外，这个空迁移必须传递给物理数据库，以便它可以将与物理数据库关联的数据库结构版本与数据库快照中记录的版本进行同步。这个版本很重要，因为它决定了哪些迁移必须应用到数据库，哪些已经应用了。

整个设计过程需要一个测试/设计数据库，如果我们操作的是已经存在的数据库，那么这个测试/设计数据库的结构必须反映实际数据库的结构 - 至少在我们想要映射的表方面。为了使设计工具能够与数据库交互，我们必须定义它们传递给`DbContext`构造函数的`DbContextOptions`选项。这些选项在设计时很重要，因为它们包含测试/设计数据库的连接字符串。如果我们创建一个实现`IDesignTimeDbContextFactory<T>`接口的类，其中`T`是我们的`DbContext`子类，设计工具可以了解我们的`DbContextOptions`选项：

```cs
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
namespace WWTravelClubDB
{
    public class LibraryDesignTimeDbContextFactory
        : IDesignTimeDbContextFactory<MainDbContext>
    {
        private const string connectionString =
            @"Server=(localdb)\mssqllocaldb;Database=wwtravelclub;
                Trusted_Connection=True;MultipleActiveResultSets=true";
        public MainDbContext CreateDbContext(params string[] args)
        {
            var builder = new DbContextOptionsBuilder<MainDbContext>();

            builder.UseSqlServer(connectionString);
            return new MainDbContext(builder.Options);
        }
    }
} 
```

`connectionString`将被 Entity Framework 用于在开发机器上安装的本地 SQL Server 实例中创建一个新数据库，并使用 Windows 凭据进行连接。您可以自由更改它以反映您的需求。

现在，我们准备创建我们的第一个迁移！让我们开始吧：

1.  让我们转到**程序包管理器控制台**，确保**WWTravelClubDB**被选为我们的默认项目。

1.  现在，输入`Add-Migration initial`并按 Enter 键发出此命令。在发出此命令之前，请验证是否已添加了`Microsoft.EntityFrameworkCore.Tools` NuGet 包，否则可能会出现“未识别的命令”错误！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_08_01.png)

图 8.1：添加第一个迁移

`initial`是我们给第一个迁移的名称。因此，一般来说，命令是`Add-Migration <迁移名称>`。当我们操作现有数据库时，必须在第一个迁移（仅在第一个迁移）中添加`-IgnoreChanges`选项，以便创建一个空迁移。有关整套命令的参考可以在*进一步阅读*部分找到。

1.  如果在创建迁移之后，但在将迁移应用到数据库之前，我们意识到我们犯了一些错误，我们可以使用`Remove-Migration`命令撤消我们的操作。如果迁移已经应用到数据库，纠正错误的最简单方法是对代码进行所有必要的更改，然后应用另一个迁移。

1.  一旦执行`Add-Migration`命令，我们的项目中会出现一个新文件夹！[](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_08_02.png)

图 8.2：Add-Migration 命令创建的文件

`20201008150827_initial.cs`是我们用易于理解的语言表达的迁移。

您可以查看代码以验证一切是否正常，您也可以修改迁移内容（只有当您足够专业时才能可靠地这样做）。每个迁移都包含一个`Up`方法和一个`Down`方法。`Up`方法表示迁移，而`Down`方法撤消其更改。因此，`Down`方法包含与`Up`方法中包含的所有操作的相反操作，按照相反的顺序。

`20201008150827_initial.Designer.cs`是 Visual Studio 的设计器代码，*不得*修改，而`MainDBContextModelSnapshot.cs`是整体数据库结构快照。如果添加了进一步的迁移，新的迁移文件及其设计器对应文件将出现，并且唯一的`MainDBContextModelSnapshot.cs`数据库结构快照将被更新以反映数据库的整体结构。

在 Windows 控制台中输入`dotnet ef migrations add initial`可以发出相同的命令。但是，此命令必须在项目的根文件夹中发出（而不是在解决方案的根文件夹中）。

可以通过在包管理器控制台中键入`Update-Database`来将迁移应用到数据库。相应的 Windows 控制台命令是`dotnet ef database update`。让我们尝试使用这个命令来创建物理数据库！

下一小节将解释如何创建 Entity Framework 无法自动创建的数据库内容。之后，在下一节中，我们将使用 Entity Framework 的配置和我们使用`dotnet ef database update`生成的数据库来创建、查询和更新数据。

## 理解存储过程和直接 SQL 命令

一些数据库结构，例如存储过程，无法通过我们之前描述的 Entity Framework Core 命令和声明自动生成。例如，可以通过`migrationBuilder.Sql("<sql scommand>")`方法在`Up`和`Down`方法中手动包含存储过程和通用 SQL 字符串。

最安全的方法是添加一个迁移而不进行任何配置更改，以便在创建时迁移为空。然后，我们可以将必要的 SQL 命令添加到此迁移的空`Up`方法中，以及在空的`Down`方法中添加它们的相反命令。将所有 SQL 字符串放在资源文件（`.resx`文件）的属性中是一个好的做法。

现在，您已经准备好通过 Entity Framework Core 与数据库进行交互了。

# 使用 Entity Framework Core 查询和更新数据

为了测试我们的 DB 层，我们需要根据与我们的库相同的.NET Core 版本向解决方案中添加一个基于控制台的项目。让我们开始吧：

1.  让我们将新的控制台项目命名为`WWTravelClubDBTest`。

1.  现在，我们需要将数据层作为控制台项目的依赖项添加到**References**节点中，然后选择**Add reference**。

1.  删除`program.cs`文件中`Main`静态方法的内容，并开始编写以下内容：

```cs
Console.WriteLine("program start: populate database, press a key to continue");
Console.ReadKey(); 
```

1.  然后，在文件顶部添加以下命名空间：

```cs
using WWTravelClubDB;
using WWTravelClubDB.Models;
using Microsoft.EntityFrameworkCore;
using System.Linq; 
```

现在，我们已经完成了准备测试项目的工作，可以尝试查询和更新数据。让我们开始创建一些数据库对象，即一些目的地和包。按照以下步骤进行：

1.  首先，我们必须创建一个适当的连接字符串的`DbContext`子类的实例。我们可以使用相同的`LibraryDesignTimeDbContextFactory`类，该类被设计工具用于获取它：

```cs
var context = new LibraryDesignTimeDbContextFactory()
    .CreateDbContext(); 
```

1.  可以通过简单地将类实例添加到我们`DbContext`子类的映射集合中来创建新行。如果`Destination`实例与其关联的包相关联，我们可以简单地将它们添加到其`Packages`属性中：

```cs
var firstDestination= new Destination
{
    Name = "Florence",
    Country = "Italy",
    Packages = new List<Package>()
    {
        new Package
        {
            Name = "Summer in Florence",
            StartValidityDate = new DateTime(2019, 6, 1),
            EndValidityDate = new DateTime(2019, 10, 1),
            DurationInDays=7,
            Price=1000
        },
        new Package
        {
            Name = "Winter in Florence",
            StartValidityDate = new DateTime(2019, 12, 1),
            EndValidityDate = new DateTime(2020, 2, 1),
            DurationInDays=7,
            Price=500
        }
    }
};
context.Destinations.Add(firstDestination);
context.SaveChanges();
Console.WriteLine(
    "DB populated: first destination id is "+
    firstDestination.Id);
Console.ReadKey(); 
```

无需指定主键，因为它们是自动生成的，并将由数据库填充。事实上，在`SaveChanges()`操作后，我们的上下文与实际数据库同步后，`firstDestination.Id`属性具有非零值。对于`Package`的主键也是如此。

当我们声明一个实体（在我们的情况下是`Package`）是另一个实体（在我们的情况下是`Destination`）的子实体，通过将其插入到父实体集合（在我们的情况下是`Packages`集合）中时，由于 Entity Framework Core 会自动推断外键（在我们的情况下是`DestinationId`），因此无需显式设置外键。创建并与`firstDestination`数据库同步后，我们可以以两种不同的方式添加更多的套餐：

+   创建一个`Package`类实例，将其`DestinationId`外键设置为`firstDestinatination.Id`，并将其添加到`context.Packages`

+   创建一个`Package`类实例，无需设置其外键，然后将其添加到其父`Destination`实例的`Packages`集合中。

后一种选项是唯一的可能性，当子实体（`Package`）与其父实体（`Destination`）一起添加，并且父实体具有自动生成的主键时，因为在这种情况下，外键在执行添加时不可用。在大多数其他情况下，前一种选项更简单，因为第二种选项要求在内存中加载父`Destination`实体，以及其`Packages`集合，即与`Destination`对象相关联的所有套餐（默认情况下，连接的实体不会通过查询加载）。

现在，假设我们想修改*佛罗伦萨*目的地，并为所有`佛罗伦萨`套餐价格增加 10%。我们该如何操作？按照以下步骤找出答案：

1.  首先，注释掉所有以前用于填充数据库的指令，但保留`DbContext`创建指令。

1.  然后，我们需要使用查询将实体加载到内存中，修改它，并调用`SaveChanges()`将我们的更改与数据库同步。

如果我们只想修改其描述，那么以下查询就足够了：

```cs
var toModify = context.Destinations
    .Where(m => m.Name == "Florence").FirstOrDefault(); 
```

1.  我们需要加载所有相关的目的地套餐，这些套餐默认情况下未加载。可以使用`Include`子句来完成，如下所示：

```cs
var toModify = context.Destinations
    .Where(m => m.Name == "Florence")
    .Include(m => m.Packages)
    .FirstOrDefault(); 
```

1.  之后，我们可以修改描述和套餐价格，如下所示：

```cs
toModify.Description = 
  "Florence is a famous historical Italian town";
foreach (var package in toModify.Packages)
   package.Price = package.Price * 1.1m;
context.SaveChanges();
var verifyChanges= context.Destinations
    .Where(m => m.Name == "Florence")
    .FirstOrDefault();
Console.WriteLine(
    "New Florence description: " +
    verifyChanges.Description);
Console.ReadKey(); 
```

如果使用`Include`方法包含的实体本身包含我们想要包含的嵌套集合，我们可以使用`ThenInclude`，如下所示：

```cs
.Include(m => m.NestedCollection)
.ThenInclude(m => m.NestedNestedCollection) 
```

由于 Entity Framework 始终尝试将每个 LINQ 翻译为单个 SQL 查询，有时生成的查询可能过于复杂和缓慢。在这种情况下，从第 5 版开始，我们可以允许 Entity Framework 将 LinQ 查询拆分为多个 SQL 查询，如下所示：

```cs
.AsSplitQuery().Include(m => m.NestedCollection)
.ThenInclude(m => m.NestedNestedCollection) 
```

通过检查`ToQueryString`方法生成的 LinQ 查询的 SQL，可以解决性能问题：

```cs
var mySQL = myLinQQuery.ToQueryString (); 
```

从第 5 版开始，包含的嵌套集合也可以使用`Where`进行过滤，如下所示：

```cs
.Include(m => m.Packages.Where(l-> l.Price < x)) 
```

到目前为止，我们执行的查询的唯一目的是更新检索到的实体。接下来，我们将解释如何检索将向用户显示和/或由复杂业务操作使用的信息。

## 将数据返回到表示层

为了保持层之间的分离，并根据每个*用例*实际需要的数据调整查询，DB 实体不会按原样发送到表示层。相反，数据将投影到包含*用例*所需信息的较小类中，这些类由表示层的调用方法实现。将数据从一层移动到另一层的对象称为**数据传输对象**（**DTOs**）。例如，让我们创建一个 DTO，其中包含在向用户返回套餐列表时值得显示的摘要信息（我们假设如果需要，用户可以通过单击他们感兴趣的套餐来获取更多详细信息）：

1.  让我们在 WWTravelClubDBTest 项目中添加一个 DTO，其中包含需要在套餐列表中显示的所有信息：

```cs
namespace WWTravelClubDBTest
{
    public class PackagesListDTO
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public decimal Price { get; set; }
        public int DurationInDays { get; set; }
        public DateTime? StartValidityDate { get; set; }
        public DateTime? EndValidityDate { get; set; }
        public string DestinationName { get; set; }
        public int DestinationId { get; set; }
        public override string ToString()
        {
            return string.Format("{0}. {1} days in {2}, price: 
            {3}", Name, DurationInDays, DestinationName, Price);
        }
    }
} 
```

我们不需要将实体加载到内存中，然后将其数据复制到 DTO 中，而是可以直接将数据库数据投影到 DTO 中，这要归功于 LINQ 的`Select`子句。这样可以最大程度地减少与数据库交换的数据量。

1.  例如，我们可以使用查询填充我们的 DTO，该查询检查所有在 8 月 10 日左右可用的包裹：

```cs
var period = new DateTime(2019, 8, 10);
var list = context.Packages
    .Where(m => period >= m.StartValidityDate
    && period <= m.EndValidityDate)
    .Select(m => new PackagesListDTO
    {
        StartValidityDate=m.StartValidityDate,
        EndValidityDate=m.EndValidityDate,
        Name=m.Name,
        DurationInDays=m.DurationInDays,
        Id=m.Id,
        Price=m.Price,
        DestinationName=m.MyDestination.Name,
        DestinationId = m.DestinationId
    })
    .ToList();
foreach (var result in list)
    Console.WriteLine(result.ToString());
Console.ReadKey(); 
```

1.  在`Select`子句中，我们还可以导航到任何相关实体以获取所需的数据。例如，前面的查询导航到相关的`Destination`实体以获取`Package`目的地名称。

1.  程序在每个`Console.ReadKey()`方法处停止，等待您按任意键。这样，您就有时间分析由我们添加到`Main`方法的所有代码片段产生的输出。

1.  现在，在解决方案资源管理器中右键单击 WWTravelClubDBTest 项目，并将其设置为启动项目。然后，运行解决方案。

现在，我们将学习如何处理不能有效映射到表示数据库表的内存集合中的即时操作的操作。

## 发出直接的 SQL 命令

并非所有的数据库操作都可以通过使用 LINQ 查询数据库并更新内存实体来高效执行。例如，计数器增量可以通过单个 SQL 指令更有效地执行。此外，如果我们定义了适当的存储过程/SQL 命令，一些操作可以以可接受的性能执行。在这些情况下，我们不得不直接向数据库发出 SQL 命令或从 Entity Framework 代码中调用数据库存储过程。有两种可能性：执行数据库操作但不返回实体的 SQL 语句，以及返回实体的 SQL 语句。

不返回实体的 SQL 命令可以通过`DbContext`方法执行，如下所示：

```cs
int DbContext.Database.ExecuteSqlRaw(string sql, params object[] parameters) 
```

参数可以在字符串中作为`{0}，{1}，...，{n}`进行引用。每个`{m}`都填充了`parameters`数组中`m`索引处包含的对象，该对象从.NET 类型转换为相应的 SQL 类型。该方法返回受影响的行数。

必须通过与这些实体相关联的映射集合的`FromSqlRaw`方法发出返回实体集合的 SQL 命令：

```cs
context.<mapped collection>.FromSqlRaw(string sql, params object[] parameters) 
```

因此，例如，返回`Package`实例的命令看起来像这样：

```cs
var results = context.Packages.FromSqlRaw("<some sql>", par1, par2, ...).ToList(); 
```

SQL 字符串和参数在`ExecuteSqlRaw`方法中的工作方式如下。以下是一个简单的例子：

```cs
var allPackages =context.Packages.FromSqlRaw(
    "SELECT * FROM Products WHERE Name = {0}",
    myPackageName) 
```

将所有 SQL 字符串放入资源文件中，并将所有`ExecuteSqlRaw`和`FromSqlRaw`调用封装在您在基于 Entity Framework Core 的数据层中定义的公共方法中，以便将特定数据库的依赖性保持在内部。

## 处理事务

对`DbContext`实例所做的所有更改都在第一次`SaveChanges`调用时作为单个事务传递。然而，有时需要在同一个事务中包含查询和更新。在这些情况下，我们必须显式处理事务。如果我们将它们放在与事务对象关联的`using`块中，那么几个 Entity Framework Core 命令可以包含在事务中：

```cs
using (var dbContextTransaction = context.Database.BeginTransaction())
try{
   ...
   ...
   dbContextTransaction.Commit();
 }
 catch
 {
   dbContextTransaction.Rollback();
 } 
```

在上述代码中，`context`是我们`DbContext`子类的一个实例。在`using`块内，可以通过调用其`Rollback`和`Commit`方法来中止和提交事务。包含在事务块中的任何`SaveChanges`调用都使用它们已经存在的事务，而不是创建新的事务。

# 部署数据层

当数据库层部署到生产环境或暂存环境时，通常已经存在一个空数据库，因此必须应用所有迁移以创建所有数据库对象。这可以通过调用`context.Database.Migrate()`来完成。`Migrate`方法应用尚未应用到数据库的迁移，因此在应用程序的生命周期中可以安全地多次调用。`context`是我们的`DbContext`类的一个实例，必须通过具有足够权限来创建表和执行迁移中包含的所有操作的连接字符串进行传递。因此，通常，此连接字符串与我们在正常应用程序操作期间使用的字符串不同。

在 Azure 上部署 Web 应用程序时，我们有机会使用我们提供的连接字符串来检查迁移。我们还可以在应用程序启动时通过调用`context.Database.Migrate()`方法来手动检查迁移。这将在*第十五章*“介绍 ASP.NET Core MVC”中详细讨论，该章节专门讨论 ASP.NET MVC Web 应用程序。

对于桌面应用程序，我们可以在应用程序安装和后续更新期间应用迁移。

在首次安装应用程序和/或后续应用程序更新时，我们可能需要使用初始数据填充一些表。对于 Web 应用程序，此操作可以在应用程序启动时执行，而对于桌面应用程序，此操作可以包含在安装中。

数据库表可以使用 Entity Framework Core 命令进行填充。但首先，我们需要验证表是否为空，以避免多次添加相同的表行。这可以使用`Any()` LINQ 方法来完成，如下面的代码所示：

```cs
if(!context.Destinations.Any())
{
    //populate here the Destinations table
} 
```

让我们来看看 Entity Framework Core 有哪些高级特性可以分享。

# 理解 Entity Framework Core 的高级特性

值得一提的一个有趣的 Entity Framework 高级特性是全局过滤器，这是在 2017 年底引入的。它们可以实现软删除和多租户表等技术，这些表由多个用户共享，每个用户只能*看到*自己的记录。

全局过滤器是使用`modelBuilder`对象定义的，该对象在`DbContext`的`OnModelCreating`方法中可用。此方法的语法如下：

```cs
modelBuilder.Entity<MyEntity>().HasQueryFilter(m => <define filter condition here>); 
```

例如，如果我们向我们的`Package`类添加一个`IsDeleted`属性，我们可以通过定义以下过滤器软删除`Package`而不从数据库中删除它：

```cs
modelBuilder.Entity<Package>().HasQueryFilter(m => !m.IsDeleted); 
```

但是，过滤器包含`DbContext`属性。因此，例如，如果我们向我们的`DbContext`子类添加一个`CurrentUserID`属性（其值在创建`DbContext`实例时设置），那么我们可以向所有引用用户 ID 的实体添加以下过滤器：

```cs
modelBuilder.Entity<Document>().HasQueryFilter(m => m.UserId == CurrentUserId); 
```

通过上述过滤器，当前登录的用户只能访问他们拥有的文档（具有他们的`UserId`的文档）。类似的技术在多租户应用程序的实现中非常有用。

另一个值得一提的有趣特性是将实体映射到不可更新的数据库查询，这是在版本 5 中引入的。

当您定义一个实体时，您可以明确定义映射的数据库表的名称或映射的可更新视图的名称：

```cs
 modelBuilder.Entity<MyEntity1>().ToTable("MyTable");
 modelBuilder.Entity<MyEntity2>().ToView("MyView"); 
```

当实体映射到视图时，数据库迁移不会生成表，因此必须由开发人员手动定义数据库视图。

如果我们想要映射实体的视图不可更新，LinQ 无法使用它将更新传递给数据库。在这种情况下，我们可以同时将相同实体映射到视图和表：

```cs
modelBuilder.Entity<MyEntity>().ToTable("MyTable").ToView("MyView"); 
```

Entity Framework 将使用视图进行查询和表进行更新。当我们创建数据库表的新版本，但又希望在所有查询中同时从旧版本的表中获取数据时，这是非常有用的。在这种情况下，我们可以定义一个视图，该视图从旧表和新表中获取数据，但只在新表上传递所有更新。

# 摘要

在本章中，我们讨论了 ORM 基础知识的基本要点以及它们为何如此有用。然后，我们描述了 Entity Framework Core。特别是，我们讨论了如何使用类注释和其他声明以及包含在`DbContext`子类中的命令来配置数据库映射。

然后，我们讨论了如何通过迁移自动创建和更新物理数据库结构，以及如何通过 Entity Framework Core 查询和传递更新到数据库。最后，我们学习了如何通过 Entity Framework Core 传递直接的 SQL 命令和事务，以及如何基于 Entity Framework Core 部署数据层。

本章还回顾了最新的 Entity Framework Core 版本中引入的一些高级功能。

在下一章中，我们将讨论 Entity Framework Core 如何与 NoSQL 数据模型一起使用，以及云中和特别是 Azure 中可用的各种存储选项。

# 问题

1.  Entity Framework Core 如何适应多种不同的数据库引擎？

1.  Entity Framework Core 中如何声明主键？

1.  Entity Framework Core 中如何声明字符串字段的长度？

1.  Entity Framework Core 中如何声明索引？

1.  Entity Framework Core 中如何声明关系？

1.  什么是两个重要的迁移命令？

1.  默认情况下，LINQ 查询是否加载相关实体？

1.  是否可能在不是数据库实体的类实例中返回数据库数据？如果是，如何？

1.  在生产和分段中如何应用迁移？

# 进一步阅读

+   有关迁移命令的更多详细信息，请参阅[`docs.microsoft.com/en-US/ef/core/miscellaneous/cli/index`](https://docs.microsoft.com/en-US/ef/core/miscellaneous/cli/index)以及其中包含的其他链接。

+   有关 Entity Framework Core 的更多详细信息，请参阅官方 Microsoft 文档：[`docs.microsoft.com/en-us/ef/core/`](https://docs.microsoft.com/en-us/ef/core/)。

+   这里可以找到一组复杂 LINQ 查询的详尽示例：[`code.msdn.microsoft.com/101-LINQ-Samples-3fb9811b`](https://code.msdn.microsoft.com/101-LINQ-Samples-3fb9811b)。


# 第九章：如何在云中选择您的数据存储

与其他云一样，Azure 提供了各种存储设备。最简单的方法是在云中定义一组可扩展的虚拟机，我们可以在其中实现自定义解决方案。例如，我们可以在云托管的虚拟机上创建 SQL Server 集群，以增加可靠性和计算能力。然而，通常情况下，自定义架构并不是最佳解决方案，并且无法充分利用云基础设施提供的机会。

因此，本章不会讨论这些自定义架构，而主要关注云中和 Azure 上可用的各种**平台即服务**（**PaaS**）存储方案。这些方案包括基于普通磁盘空间、关系型数据库、NoSQL 数据库和 Redis 等内存数据存储的可扩展解决方案。

选择更合适的存储类型不仅基于应用程序的功能要求，还基于性能和扩展要求。事实上，尽管在处理资源时进行扩展会导致性能线性增加，但扩展存储资源并不一定意味着性能会有可接受的增加。简而言之，无论您如何复制数据存储设备，如果多个请求影响相同的数据块，它们将始终排队等待相同的时间来访问它！

扩展数据会导致读操作吞吐量线性增加，因为每个副本可以处理不同的请求，但对于写操作的吞吐量并不意味着同样的增加，因为相同数据块的所有副本都必须更新！因此，需要更复杂的技术来扩展存储设备，并非所有存储引擎都能够同样良好地扩展。

在所有场景中，关系型数据库并不都能很好地扩展。因此，扩展需求和地理数据分布的需求在选择存储引擎以及 SaaS 提供方面起着基本作用。

在本章中，我们将涵盖以下主题：

+   了解不同用途的不同存储库

+   在关系型或 NoSQL 存储之间进行选择

+   Azure Cosmos DB - 管理多大陆数据库的机会

+   用例 - 存储数据

让我们开始吧！

# 技术要求

本章需要您具备以下内容：

+   Visual Studio 2019 免费社区版或更高版本，安装了所有数据库工具组件。

+   免费的 Azure 账户。*第一章*的*创建 Azure 账户*小节解释了如何创建账户。

+   为了获得更好的开发体验，我们建议您还安装 Cosmos DB 的本地模拟器，可以在[`aka.ms/cosmosdb-emulator`](https://aka.ms/cosmosdb-emulator)找到。

# 了解不同用途的不同存储库

本节描述了最流行的数据存储技术提供的功能。主要关注它们能够满足的功能要求。性能和扩展功能将在下一节中进行分析，该节专门比较关系型和 NoSQL 数据库。

在 Azure 中，可以通过在所有 Azure 门户页面顶部的搜索栏中输入产品名称来找到各种产品。

以下小节描述了我们在 C#项目中可以使用的各种数据库类型。

## 关系型数据库

关系数据库是最常见和研究的存储类型。随着它们的发展，社会保证了高水平的服务和无数的存储数据。已经设计了数十种应用程序来存储这种类型的数据库中的数据，我们可以在银行、商店、工业等领域找到它们。当您将数据存储在关系数据库中时，基本原则是定义您将在其中保存的实体和属性，并定义这些实体之间的正确关系。

几十年来，关系数据库是设计大型项目所想象的唯一选择。世界上许多大公司都建立了自己的数据库管理系统。Oracle、MySQL 和 MS SQL Server 被许多人列为您可以信任存储数据的数据库。

通常，云提供多种数据库引擎。Azure 提供各种流行的数据库引擎，如 Oracle、MySQL 和 SQL Server（Azure SQL）。

关于 Oracle 数据库引擎，Azure 提供可配置的虚拟机，上面安装了各种 Oracle 版本，您可以通过在 Azure 门户搜索栏中键入`Oracle`后获得的建议轻松验证。Azure 的费用不包括 Oracle 许可证；它们只包括计算时间，因此您必须自行携带许可证到 Azure。

在 Azure 上使用 MySQL，您需要支付使用私有服务器实例的费用。您产生的费用取决于您拥有的核心数、必须分配的内存量以及备份保留时间。

MySQL 实例是冗余的，您可以选择本地或地理分布式冗余：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_09_01.png)

图 9.1：在 Azure 上创建 MySQL 服务器

Azure SQL 是最灵活的选择。在这里，您可以配置每个数据库使用的资源。创建数据库时，您可以选择将其放置在现有服务器实例上，或创建一个新实例。在定义解决方案时，您可以选择几种定价选项，Azure 会不断增加它们，以确保您能够处理云中的数据。基本上，它们因您需要的计算能力而异。

例如，在**数据库事务单位**（**DTUs**）模型中，费用基于已预留的数据库存储容量和由参考工作负载确定的 I/O 操作、CPU 使用率和内存使用率的线性组合。粗略地说，当您增加 DTUs 时，最大的数据库性能会线性增加。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_09_02.png)

图 9.2：创建 Azure SQL 数据库

您还可以通过启用读取扩展来配置数据复制。这样，您可以提高读取操作的性能。备份保留对于每个提供级别（基本、标准和高级）都是固定的。

如果您选择**是**作为**是否要使用 SQL 弹性池？**的答案，数据库将被添加到弹性池中。添加到同一弹性池的数据库将共享其资源，因此未被数据库使用的资源可以在其他数据库的 CPU 使用高峰期间使用。值得一提的是，弹性池只能包含托管在同一服务器实例上的数据库。弹性池是优化资源使用以减少成本的有效方式。

## NoSQL 数据库

关系数据库带来的最大挑战之一是与数据库结构模式更改相关的问题。本世纪初所需的变化的灵活性带来了使用新数据库样式的机会，称为 NoSQL。这里有几种类型的 NoSQL 数据库：

+   **面向文档的数据库**：最常见的数据库类型，其中您有一个称为文档的键和复杂数据。

+   **图数据库**：社交媒体倾向于使用这种类型的数据库，因为数据存储为图形。

+   **键值数据库**：用于实现缓存的有用数据库，因为您有机会存储键值对。

+   **宽列存储数据库**：每行中相同的列可以存储不同的数据。

在 NoSQL 数据库中，关系表被更一般的集合所取代，这些集合可以包含异构的 JSON 对象。也就是说，集合没有预定义的结构，也没有预定义的字段长度约束（对于字符串），但可以包含任何类型的对象。与每个集合关联的唯一结构约束是充当主键的属性的名称。

更具体地说，每个集合条目都可以包含嵌套对象和嵌套在对象属性中的对象集合，即在关系数据库中包含在不同表中并通过外部键连接的相关实体。在 NoSQL 中，数据库可以嵌套在其父实体中。由于集合条目包含复杂的嵌套对象而不是简单的属性/值对，因此条目不被称为元组或行，而是*文档*。

无法在属于同一集合或不同集合的文档之间定义关系和/或外部键约束。如果文档在其属性中包含另一个文档的主键，那么它就自担风险。开发人员有责任维护和保持这些一致的引用。

最后，由于 NoSQL 存储相当便宜，整个二进制文件可以作为文档属性的值存储为 Base64 字符串。开发人员可以定义规则来决定在集合中索引哪些属性。由于文档是嵌套对象，属性是树路径。通常，默认情况下，所有路径都被索引，但您可以指定要索引的路径和子路径的集合。

NoSQL 数据库可以使用 SQL 的子集或基于 JSON 的语言进行查询，其中查询是 JSON 对象，其路径表示要查询的属性，其值表示已应用于它们的查询约束。

在关系数据库中，可以通过一对多关系来模拟在文档中嵌套子对象的可能性。但是，在关系数据库中，我们被迫重新定义所有相关表的确切结构，而 NoSQL 集合不对其包含的对象施加任何预定义的结构。唯一的约束是每个文档必须为主键属性提供唯一值。因此，当我们的对象结构非常可变时，NoSQL 数据库是唯一的选择。

然而，通常它们被选择是因为它们在扩展读写操作方面的性能优势，更一般地说，在分布式环境中的性能优势。它们的性能特性将在下一节中进行讨论，该节将它们与关系数据库进行比较。

图形数据模型是完全无结构文档的极端情况。整个数据库是一个图形，其中查询可以添加、更改和删除图形文档。

在这种情况下，我们有两种文档：节点和关系。虽然关系具有明确定义的结构（由关系连接的节点的主键加上关系的名称），但节点根本没有结构，因为在节点更新操作期间，属性及其值会被添加在一起。图形数据模型旨在表示人和他们操纵的对象（媒体、帖子等）以及它们在*社交应用程序*中的关系的特征。Gremlin 语言是专门为查询图形数据模型而设计的。我们不会在本章中讨论这一点，但在*进一步阅读*部分中有参考资料。

NoSQL 数据库将在本章的其余部分中进行详细分析，这些部分专门描述了 Azure Cosmos DB 并将其与关系数据库进行比较。

## Redis

`Redis`是基于键值对的分布式并发内存存储，支持分布式排队。它可以用作永久的内存存储，以及数据库数据的 Web 应用程序缓存。或者，它可以用作预渲染内容的缓存。

`Redis`还可以用于存储 Web 应用程序的用户会话数据。事实上，`ASP.NET Core`支持会话数据，以克服`HTTP`协议是无状态的事实。更具体地说，保持在页面更改之间的用户数据存储在服务器端存储中，例如`Redis`，并由存储在`cookies`中的会话密钥索引。

与云中的`Redis`服务器的交互通常基于提供易于使用界面的客户端实现。`.NET`和`.NET Core`的客户端可以通过`StackExchange.Redis` `NuGet`包获得。`StackExchange.Redis`客户端的基本操作已在[`stackexchange.github.io/StackExchange.Redis/Basics`](https://stackexchange.github.io/StackExchange.Redis/Basics)中记录，完整文档可以在[`stackexchange.github.io/StackExchange.Redis`](https://stackexchange.github.io/StackExchange.Redis)中找到。

在`Azure`上定义`Redis`服务器的用户界面非常简单：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_09_03.png)

图 9.3：创建`Redis`缓存

**定价层**下拉菜单允许我们选择可用的内存/复制选项之一。可以在[`docs.microsoft.com/en-us/azure/azure-cache-for-redis/cache-dotnet-core-quickstart`](https://docs.microsoft.com/en-us/azure/azure-cache-for-redis/cache-dotnet-core-quickstart)找到一个快速入门指南，该指南解释了如何在`.NET Core`客户端中使用`Azure Redis`凭据和`URI`。

## `Azure`存储账户

所有云都提供可扩展和冗余的通用磁盘内存，您可以将其用作虚拟机中的虚拟磁盘和/或外部文件存储。`Azure`的*存储账户*磁盘空间也可以结构化为**表**和**队列**。如果您需要廉价的`blob`存储，可以考虑使用此选项。但是，正如我们之前提到的，还有更复杂的选项。根据您的情况，`Azure NoSQL`数据库比表更好，`Azure Redis`比`Azure`存储队列更好。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_09_04.png)

图 9.4：创建存储账户

在本章的其余部分，我们将专注于`NoSQL`数据库以及它们与关系数据库的区别。接下来，我们将看看如何在两者之间进行选择。

# 在结构化或`NoSQL`存储之间进行选择

作为软件架构师，您可能会考虑结构化和`NoSQL`存储的一些方面，以决定最适合您的存储选项。在许多情况下，两者都是需要的。关键点在于您的数据有多有组织以及数据库将变得多大。

在前一节中，我们指出当数据几乎没有预定义的结构时，应优先选择`NoSQL`数据库。`NoSQL`数据库不仅使可变属性靠近其所有者，而且还使一些相关对象靠近，因为它们允许将相关对象嵌套在属性和集合中。

在关系数据库中可以表示非结构化数据，因为元组`t`的可变属性可以放在一个包含属性名称、属性值和`t`的外部键的连接表中。然而，在这种情况下的问题是性能。事实上，属于单个对象的属性值将分散在可用内存空间中。在小型数据库中，“分散在可用内存空间中”意味着远离但在同一磁盘上；在较大的数据库中，它意味着远离但在不同的磁盘单元中；在分布式云环境中，它意味着远离但在不同的 - 也可能是地理分布的 - 服务器中。

在 NoSQL 数据库设计中，我们总是试图将所有可能一起处理的相关对象放入单个条目中。访问频率较低的相关对象放在不同的条目中。由于外部键约束不会自动执行，而且 NoSQL 事务非常灵活，开发人员可以在性能和一致性之间选择最佳折衷方案。

因此，我们可以得出结论，当通常一起访问的表可以被存储在一起时，关系数据库的表现良好。另一方面，NoSQL 数据库会自动确保相关数据保持在一起，因为每个条目都将大部分相关数据作为嵌套对象保存在其中。因此，当它们分布到不同的内存和不同地理分布的服务器时，NoSQL 数据库的表现更好。

不幸的是，扩展存储写操作的唯一方法是根据*分片键*的值将集合条目分布到多个服务器上。例如，我们可以将所有以**A**开头的用户名记录放在一个服务器上，将以**B**开头的用户名记录放在另一个服务器上，依此类推。这样，具有不同起始字母的用户名的写操作可以并行执行，确保写吞吐量随着服务器数量的增加而线性增加。

然而，如果一个*分片*集合与其他几个集合相关联，就无法保证相关记录会被放在同一台服务器上。此外，将不同的集合放在不同的服务器上而不使用集合分片会使写吞吐量线性增加，直到达到单个服务器上的单个集合的限制，但这并不能解决被迫在不同服务器上执行多个操作以检索或更新通常一起处理的数据的问题。

这个问题对关系数据库的性能造成了灾难性的影响，如果访问相关的分布式对象必须是事务性的和/或必须确保结构约束（如外部键约束）不被违反。在这种情况下，所有相关的对象在事务期间必须被阻塞，防止其他请求在耗时的分布式操作的整个生命周期内访问它们。

NoSQL 数据库不会遇到这个问题，并且在分片和因此写扩展输出方面表现更好。这是因为它们不会将相关数据分布到不同的存储单元，而是将它们存储为同一数据库条目的嵌套对象。另一方面，它们遇到了不支持事务的不同问题。

值得一提的是，有些情况下关系数据库在分片时表现良好。一个典型的例子是多租户应用。在多租户应用中，所有条目集合可以被分成不重叠的集合，称为**租户**。只有属于同一个租户的条目才能相互引用，因此如果所有集合都按照它们的对象租户以相同的方式分片，那么所有相关记录最终都会在同一个分片中，也就是在同一个服务器上，并且可以被高效地导航。

多租户应用在云中并不罕见，因为所有为多个不同用户提供相同服务的应用通常都是作为多租户应用实现的，其中每个租户对应一个用户订阅。因此，关系数据库被设计为在云中工作，例如 Azure SQL Server，并通常为多租户应用提供分片选项。通常，分片不是云服务，必须使用数据库引擎命令来定义。在这里，我们不会描述如何使用 Azure SQL Server 定义分片，但*进一步阅读*部分包含了官方微软文档的链接。

总之，关系数据库提供了数据的纯逻辑视图，与实际存储方式无关，并使用声明性语言来查询和更新数据。这简化了开发和系统维护，但在需要写入扩展的分布式环境中可能会导致性能问题。在 NoSQL 数据库中，您必须手动处理有关如何存储数据以及所有更新和查询操作的一些过程性细节，但这使您能够在需要读取和写入扩展的分布式环境中优化性能。

在下一节中，我们将介绍 Azure Cosmos DB，这是 Azure 的主要 NoSQL 产品。

# Azure Cosmos DB - 管理多大陆数据库的机会

Azure Cosmos DB 是 Azure 的主要 NoSQL 产品。Azure Cosmos DB 具有自己的界面，是 SQL 的子集，但可以配置为具有 MongoDB 接口。它还可以配置为可以使用 Gremlin 查询的图形数据模型。Cosmos DB 允许复制以实现容错和读取扩展，并且副本可以在地理上分布以优化通信性能。此外，您可以指定所有副本放置在哪个数据中心。用户还可以选择启用所有副本的写入，以便在进行写入的地理区域立即可用。通过分片实现写入扩展，用户可以通过定义要用作分片键的属性来配置分片。

## 创建 Azure Cosmos DB 帐户

您可以通过在 Azure 门户搜索栏中键入`Cosmos DB`并单击**添加**来定义 Cosmos DB 帐户。将出现以下页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_09_05.png)

图 9.5：创建 Azure Cosmos DB 帐户

您选择的帐户名称将在资源 URI 中用作`{account_name}.documents.azure.com`。**API**下拉菜单可让您选择所需的接口类型（例如 SQL、MongoDB 或 Gremlin）。然后，您可以决定主数据库将放置在哪个数据中心，以及是否要启用地理分布式复制。启用地理分布式复制后，您可以选择要使用的副本数量以及放置它们的位置。

微软一直在改进其许多 Azure 服务。在撰写本书时，容量模式和笔记本的无服务器选项处于预览状态。了解任何 Azure 组件的新功能的最佳方法是不时查看其文档。

**多区域写入**切换允许您在地理分布的副本上启用写入。如果不这样做，所有写操作将被路由到主数据中心。最后，您还可以在创建过程中定义备份策略和加密。

## 创建 Azure Cosmos 容器

创建帐户后，选择**Data Explorer**来创建数据库和其中的容器。容器是预留吞吐量和存储的可扩展单位。

由于数据库只有名称而没有配置，您可以直接添加一个容器，然后将其放置在希望放置它的数据库中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_09_06.png)

图 9.6：在 Azure Cosmos DB 中添加容器

在这里，您可以决定数据库和容器的名称以及用于分片的属性（分区键）。由于 NoSQL 条目是对象树，因此属性名称被指定为路径。您还可以添加值必须唯一的属性。

然而，唯一性 ID 在每个分片内进行检查，因此此选项仅在某些情况下有用，例如多租户应用程序（其中每个租户包含在单个分片中）。费用取决于您选择的集合吞吐量。

这是您需要将所有资源参数定位到您的需求的地方。吞吐量以每秒请求单位表示，其中每秒请求单位定义为执行每秒 1 KB 读取时的吞吐量。因此，如果选择*预留数据库吞吐量*选项，则所选的吞吐量将与整个数据库共享，而不是作为单个集合保留。

## 访问 Azure Cosmos 数据

创建 Azure Cosmos 容器后，您将能够访问数据。要获取连接信息，您可以选择**Keys**菜单。在那里，您将看到连接到您的应用程序的 Cosmos DB 帐户所需的所有信息。**连接信息页面**将为您提供帐户 URI 和两个连接密钥，这两个密钥可以互换使用以连接到帐户。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_09_07.png)

图 9.7：连接信息页面

还有具有只读权限的密钥。每个密钥都可以重新生成，每个帐户都有两个等效的密钥，就像许多其他 Azure 组件一样。这种方法使操作能够有效地处理；也就是说，当一个密钥被更改时，另一个密钥被保留。因此，在升级到新密钥之前，现有应用程序可以继续使用另一个密钥。 

## 定义数据库一致性

考虑到您处于分布式数据库的上下文中，Azure Cosmos DB 使您能够定义您将拥有的默认读一致性级别。通过在 Cosmos DB 帐户的主菜单中选择**默认一致性**，您可以选择要应用于所有容器的默认复制一致性。

可以在数据资源管理器或以编程方式中覆盖每个容器的默认设置。读/写操作中的一致性问题是数据复制的结果。具体来说，如果读操作在接收到不同部分更新的不同副本上执行，则各种读操作的结果可能不一致。

以下是可用的一致性级别。这些级别已经按从最弱到最强的顺序排列：

+   **最终一致性**：足够的时间过去后，如果没有进一步的写操作，所有读取将收敛并应用所有写操作。写入的顺序也不能保证，因此在处理写入时，您可能会读取先前读取的较早版本。

+   **一致性前缀**：所有写操作在所有副本上以相同的顺序执行。因此，如果有`n`个写操作，每次读取都与应用前`m`个写操作的结果一致，其中`m`小于或等于`n`。

+   **会话**：这与一致性前缀相同，但还保证每个写入者在所有后续读取操作中看到其自己写入的结果，并且每个读取者的后续读取是一致的（要么是相同的数据库，要么是更新的版本）。

+   **有界陈旧性**：这与延迟时间`Delta`或多个操作`N`相关联。每次读取都会看到在时间`Delta`（或最后`N`次操作）之前执行的所有写操作的结果。也就是说，它的读取与最大时间延迟`Delta`（或最大操作延迟`N`）的所有写操作的结果收敛。

+   **强一致性**：这是有界陈旧性与`Delta = 0`相结合。在这里，每次读取都反映了所有先前的写操作的结果。

最强的一致性可以通过牺牲性能来获得。默认情况下，一致性设置为**Session**，这是一致性和性能之间的良好折衷。较低级别的一致性在应用程序中很难处理，通常只有在会话是只读或只写时才可接受。

如果您在数据库容器的**Data Explorer**菜单中选择**Settings**选项，您可以配置要对哪些路径进行索引以及对每个路径的每种数据类型应用哪种类型的索引。配置由 JSON 对象组成。让我们分析其各种属性：

```cs
{
    "indexingMode": "consistent",
    "automatic": true,
    ... 
```

如果将`indexingMode`设置为`none`而不是`consistent`，则不会生成索引，并且集合可以用作由集合主键索引的键值字典。在这种情况下，不会生成**次要**索引，因此无法有效地进行搜索。当`automatic`设置为`true`时，所有文档属性都会自动索引：

```cs
{
    ...
    "includedPaths": [
        {
            "path": "/*",
            "indexes": [
                {
                    "kind": "Range",
                    "dataType": "Number",
                    "precision": -1
                },
                {
                    "kind": "Range",
                    "dataType": "String",
                    "precision": -1
                },
                {
                    "kind": "Spatial",
                    "dataType": "Point"
                }
            ]
        }
    ]
},
... 
```

`IncludedPaths`中的每个条目都指定了一个路径模式，例如`/subpath1/subpath2/?`（设置仅适用于`/subpath1/subpath2/property`）或`/subpath1/subpath2/*`（设置适用于以`/subpath1/subpath2/`开头的所有路径）。

当需要将设置应用于集合属性中包含的子对象时，模式包含`[]`符号；例如，`/subpath1/subpath2/[]/?`，`/subpath1/subpath2/[]/childpath1/?`等。设置指定要应用于每种数据类型（字符串、数字、地理点等）的索引类型。范围索引用于比较操作，而哈希索引在需要进行相等比较时更有效。

可以指定精度，即在所有索引键中使用的最大字符或数字的数量。`-1`表示最大精度，始终建议使用：

```cs
 ...
    "excludedPaths": [
   {
            "path": "/\"_etag\"/?"
        }
    ] 
```

`excludedPaths`中包含的路径根本不被索引。索引设置也可以以编程方式指定。

在这里，您有两种连接到 Cosmos DB 的选项：使用首选编程语言的官方客户端的版本，或者使用 Cosmos DB 的 Entity Framework Core 提供程序。在接下来的小节中，我们将看看这两个选项。然后，我们将描述如何使用 Cosmos DB 的 Entity Framework Core 提供程序，并提供一个实际示例。

## Cosmos DB 客户端

.NET 5 的 Cosmos DB 客户端可通过`Microsoft.Azure.Cosmos` NuGet 包获得。它提供了对所有 Cosmos DB 功能的完全控制，而 Cosmos DB Entity Framework 提供程序更易于使用，但隐藏了一些 Cosmos DB 的特殊性。按照以下步骤通过.NET 5 的官方 Cosmos DB 客户端与 Cosmos DB 进行交互。

以下代码示例显示了使用客户端组件创建数据库和容器。任何操作都需要创建客户端对象。不要忘记，当您不再需要它时，必须通过调用其`Dispose`方法（或将引用它的代码封装在`using`语句中）来处理客户端：

```cs
 public static async Task CreateCosmosDB()
{
    using var cosmosClient = new CosmosClient(endpoint, key);
    Database database = await 
        cosmosClient.CreateDatabaseIfNotExistsAsync(databaseId);
    ContainerProperties cp = new ContainerProperties(containerId,
        "/DestinationName");
    Container container = await database.CreateContainerIfNotExistsAsync(cp);
    await AddItemsToContainerAsync(container);
} 
```

在创建集合时，可以传递`ContainerProperties`对象，其中可以指定一致性级别、如何对属性进行索引以及所有其他集合功能。

然后，您必须定义与您需要在集合中操作的 JSON 文档结构相对应的.NET 类。如果它们不相等，您还可以使用`JsonProperty`属性将类属性名称映射到 JSON 名称：

```cs
public class Destination
{
    [JsonProperty(PropertyName = "id")]
    public string Id { get; set; }
    public string DestinationName { get; set; }
    public string Country { get; set; }
    public string Description { get; set; }
    public Package[] Packages { get; set; }
} 
```

一旦您拥有所有必要的类，您可以使用客户端方法`ReadItemAsync`，`CreateItemAsync`和`DeleteItemAsync`。您还可以使用接受 SQL 命令的`QueryDefinition`对象来查询数据。您可以在[`docs.microsoft.com/en-us/azure/cosmos-db/sql-api-get-started`](https://docs.microsoft.com/en-us/azure/cosmos-db/sql-api-get-started)找到有关此库的完整介绍。

## Cosmos DB Entity Framework Core 提供程序

Entity Framework Core 的 Cosmos DB 提供程序包含在`Microsoft.EntityFrameworkCore.Cosmos` NuGet 包中。一旦将其添加到项目中，您可以以类似的方式进行操作，就像在*第八章*中使用 SQL Server 提供程序时一样，但有一些不同之处。让我们看看：

+   由于 Cosmos DB 数据库没有结构需要更新，因此没有迁移。相反，它们有一种方法可以确保数据库以及所有必要的集合被创建：

```cs
context.Database.EnsureCreated(); 
```

+   默认情况下，从`DBContext`映射到唯一容器的`DbSet<T>`属性，因为这是最便宜的选项。您可以通过显式指定要将某些实体映射到哪个容器来覆盖此默认设置，方法是使用以下配置指令：

```cs
builder.Entity<MyEntity>()
     .ToContainer("collection-name"); 
```

+   实体类上唯一有用的注释是`Key`属性，当主键不叫`Id`时，它就变得强制性了。

+   主键必须是字符串，不能自动增加以避免在分布式环境中出现同步问题。主键的唯一性可以通过生成 GUID 并将其转换为字符串来确保。

+   在定义实体之间的关系时，您可以指定一个实体或实体集合是由另一个实体拥有的，这种情况下它将与父实体一起存储。

我们将在下一节中查看 Cosmos DB 的 Entity Framework 提供程序的用法。

# 用例-存储数据

现在我们已经学会了如何使用 NoSQL，我们必须决定 NoSQL 数据库是否适合我们的书籍使用案例 WWTravelClub 应用程序。我们需要存储以下数据系列：

+   **有关可用目的地和套餐的信息**：此数据的相关操作是读取，因为套餐和目的地不经常更改。但是，它们必须尽可能快地从世界各地访问，以确保用户在浏览可用选项时有愉快的体验。因此，可能存在具有地理分布副本的分布式关系数据库，但并非必需，因为套餐可以存储在更便宜的 NoSQL 数据库中。

+   **目的地评论**：在这种情况下，分布式写操作会产生不可忽略的影响。此外，大多数写入都是添加，因为评论通常不会更新。添加受益于分片，并且不像更新那样会导致一致性问题。因此，这些数据的最佳选择是 NoSQL 集合。

+   **预订**：在这种情况下，一致性错误是不可接受的，因为它们可能导致超额预订。读取和写入具有可比较的影响，但我们需要可靠的事务和良好的一致性检查。幸运的是，数据可以组织在一个多租户数据库中，其中租户是目的地，因为属于不同目的地的预订信息是完全不相关的。因此，我们可以使用分片的 SQL Azure 数据库实例。

总之，第一和第二个要点的数据的最佳选择是 Cosmos DB，而第三个要点的最佳选择是 Azure SQL Server。实际应用可能需要对所有数据操作及其频率进行更详细的分析。在某些情况下，值得为各种可能的选项实施原型，并在所有选项上使用典型工作负载执行性能测试。

在本节的其余部分，我们将迁移我们在*第八章* *与 C#中的数据交互-Entity Framework Core*中查看的目的地/套餐数据层到 Cosmos DB。

## 使用 Cosmos DB 实现目的地/套餐数据库

让我们继续按照以下步骤将我们在*第八章* *与 C#中的数据交互-Entity Framework Core*中构建的数据库示例迁移到 Cosmos DB：

1.  首先，我们需要复制 WWTravelClubDB 项目，并将`WWTravelClubDBCosmo`作为新的根文件夹。

1.  打开项目并删除迁移文件夹，因为不再需要迁移。

1.  我们需要用 Cosmos DB 提供程序替换 SQL Server Entity Framework 提供程序。为此，请转到**管理 NuGet 包**并卸载`Microsoft.EntityFrameworkCore.SqlServer` NuGet 包。然后，安装`Microsoft.EntityFrameworkCore.Cosmos` NuGet 包。

1.  然后，在`Destination`和`Package`实体上执行以下操作：

+   删除所有数据注释。

+   为它们的 `Id` 属性添加 `[Key]` 属性，因为这对于 Cosmos DB 提供程序是强制性的。

+   将 `Package` 和 `Destination` 的 `Id` 属性的类型，以及 `PackagesListDTO` 类从 `int` 转换为 `string`。我们还需要将 `Package` 和 `PackagesListDTO` 类中的 `DestinationId` 外部引用转换为 `string`。实际上，在分布式数据库中，使用 GUID 生成的字符串作为键是最佳选择，因为在表数据分布在多个服务器之间时，很难维护标识计数器。

1.  在 `MainDBContext` 文件中，我们需要指定与目的地相关的包必须存储在目的地文档本身内。这可以通过在 `OnModelCreatingmethod` 方法中替换 Destination-Package 关系配置来实现，代码如下：

```cs
builder.Entity<Destination>()
    .OwnsMany(m =>m.Packages); 
```

1.  在这里，我们必须用 `OwnsMany` 替换 `HasMany`。没有等效于 `WithOne`，因为一旦实体被拥有，它必须只有一个所有者，并且 `MyDestination` 属性包含对父实体的指针的事实从其类型中显而易见。Cosmos DB 也允许使用 `HasMany`，但在这种情况下，这两个实体不是相互嵌套的。还有一个用于将单个实体嵌套在其他实体内的 `OwnOne` 配置方法。

1.  实际上，对于关系数据库，`OwnsMany` 和 `OwnsOne` 都是可用的，但在这种情况下，`HasMany` 和 `HasOne` 之间的区别在于子实体会自动包含在返回其父实体的所有查询中，无需指定 `Include` LINQ 子句。但是，子实体仍然存储在单独的表中。

1.  `LibraryDesignTimeDbContextFactory` 必须修改为使用 Cosmos DB 连接数据，如下所示的代码：

```cs
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
namespace WWTravelClubDB
{
    public class LibraryDesignTimeDbContextFactory
        : IDesignTimeDbContextFactory<MainDBContext>
    {
        private const string endpoint = "<your account endpoint>";
        private const string key = "<your account key>";
        private const string databaseName = "packagesdb";
        public "MainDBContext CreateDbContext"(params string[] args)
        {
            var builder = new DbContextOptionsBuilder<Main
DBContext>();
builder.UseCosmos(endpoint, key, databaseName);
            return new MainDBContext(builder.Options);
        }
    }
} 
```

1.  最后，在我们的测试控制台中，我们必须明确使用 GUID 创建所有实体主键：

```cs
var context = new LibraryDesignTimeDbContextFactory()
    .CreateDbContext();
context.Database.EnsureCreated();
var firstDestination = new Destination
{
    Id = Guid.NewGuid().ToString(),
    Name = "Florence",
    Country = "Italy",
    Packages = new List<Package>()
    {
    new Package
    {
        Id=Guid.NewGuid().ToString(),
        Name = "Summer in Florence",
        StartValidityDate = new DateTime(2019, 6, 1),
        EndValidityDate = new DateTime(2019, 10, 1),
        DuratioInDays=7,
        Price=1000
    },
    new Package
    {
        Id=Guid.NewGuid().ToString(),
        Name = "Winter in Florence",
        StartValidityDate = new DateTime(2019, 12, 1),
        EndValidityDate = new DateTime(2020, 2, 1),
        DuratioInDays=7,
        Price=500
    }
    }
}; 
```

1.  在这里，我们调用 `context.Database.EnsureCreated()` 而不是应用迁移，因为我们只需要创建数据库。一旦数据库和集合被创建，我们可以从 Azure 门户微调它们的设置。希望未来版本的 Cosmos DB Entity Framework Core 提供程序将允许我们指定所有集合选项。

1.  最后，以 `context.Packages.Where...` 开头的最终查询必须进行修改，因为查询不能以嵌套在其他文档中的实体（在我们的情况下是 `Packages` 实体）开头。因此，我们必须从我们的 `DBContext` 中唯一的根 `DbSet<T>` 属性开始查询，即 `Destinations`。我们可以通过 `SelectMany` 方法从列出外部集合转到列出所有内部集合，该方法执行所有嵌套 `Packages` 集合的逻辑合并。但是，由于 `CosmosDB` SQL 不支持 `SelectMany`，我们必须强制在客户端上模拟 `SelectMany`，如下所示的代码：

```cs
var list = context.Destinations
    .AsEnumerable() // move computation on the client side
    .SelectMany(m =>m.Packages)
    .Where(m => period >= m.StartValidityDate....)
    ... 
```

1.  查询的其余部分保持不变。如果现在运行项目，您应该看到与 SQL Server 情况下收到的相同输出（除了主键值）。

1.  执行程序后，转到您的 Cosmos DB 帐户。您应该看到类似以下内容的内容：![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_09_08.png)

图 9.8：执行结果

根据要求，包已嵌套在其目的地内，并且 Entity Framework Core 创建了一个与 `DBContext` 类同名的唯一集合。

如果您想继续尝试 Cosmos DB 开发而不浪费所有免费的 Azure 门户信用，您可以安装位于以下链接的 Cosmos DB 模拟器：[`aka.ms/cosmosdb-emulator`](https://aka.ms/cosmosdb-emulator)。

# 总结

在本章中，我们了解了 Azure 中可用的主要存储选项，并学会了何时使用它们。然后，我们比较了关系数据库和 NoSQL 数据库。我们指出，关系数据库提供自动一致性检查和事务隔离，但 NoSQL 数据库更便宜，性能更好，特别是在分布式写入占平均工作负载的高比例时。

然后，我们描述了 Azure 的主要 NoSQL 选项 Cosmos DB，并解释了如何配置它以及如何与客户端连接。

最后，我们学习了如何使用实体框架核心与 Cosmos DB 进行交互，并查看了基于 WWTravelClubDB 用例的实际示例。在这里，我们学习了如何在应用程序中涉及的所有数据族之间决定关系和 NoSQL 数据库之间的选择。这样，您可以选择确保在每个应用程序中数据一致性、速度和并行访问之间取得最佳折衷的数据存储方式。

在下一章中，我们将学习有关无服务器和 Azure 函数的所有内容。

# 问题

1.  Redis 是否是关系数据库的有效替代品？

1.  NoSQL 数据库是否是关系数据库的有效替代品？

1.  在关系数据库中，哪种操作更难扩展？

1.  NoSQL 数据库的主要弱点是什么？它们的主要优势是什么？

1.  您能列出所有 Cosmos DB 的一致性级别吗？

1.  我们可以在 Cosmos DB 中使用自增整数键吗？

1.  哪种实体框架配置方法用于将实体存储在其相关的父文档中？

1.  在 Cosmos DB 中，可以有效地搜索嵌套集合吗？

# 进一步阅读

+   在本章中，我们没有讨论如何在 Azure SQL 中定义分片。如果您想了解更多信息，请访问官方文档链接：[`docs.microsoft.com/en-us/azure/sql-database/sql-database-elastic-scale-introduction`](https://docs.microsoft.com/en-us/azure/sql-database/sql-database-elastic-scale-introduction)。

+   Cosmos DB 在本章中有详细描述，但更多细节可以在官方文档中找到：[`docs.microsoft.com/en-us/azure/cosmos-db/`](https://docs.microsoft.com/en-us/azure/cosmos-db/)。

+   以下是 Gremlin 语言的参考，它受 Cosmos DB 支持：[`tinkerpop.apache.org/docs/current/reference/#graph-traversal-steps`](http://tinkerpop.apache.org/docs/current/reference/#graph-traversal-steps)。

+   以下是 Cosmos DB 图形数据模型的一般描述：[`docs.microsoft.com/en-us/azure/cosmos-db/graph-introduction`](https://docs.microsoft.com/en-us/azure/cosmos-db/graph-introduction)。

+   有关如何使用 Cosmos DB 的官方.NET 客户端的详细信息，请参阅[`docs.microsoft.com/en-us/azure/cosmos-db/sql-api-dotnetcore-get-started`](https://docs.microsoft.com/en-us/azure/cosmos-db/sql-api-dotnetcore-get-started)。我们在本章中提到的`MvcControlsToolkit.Business.DocumentDB` NuGet 包的良好介绍是 DNCMagazine 第 34 期中包含的*使用 DocumentDB 包快速进行 Azure Cosmos DB 开发*文章。可从[`www.dotnetcurry.com/microsoft-azure/aspnet-core-cosmos-db-documentdb`](https://www.dotnetcurry.com/microsoft-azure/aspnet-core-cosmos-db-documentdb)下载。


# 第十章：使用 Azure Functions

正如我们在*第四章*中提到的，无服务器架构是提供灵活软件解决方案的最新方式之一。为此，Microsoft Azure 提供了 Azure Functions，这是一种事件驱动、无服务器且可扩展的技术，可以加速您的项目开发。本章的主要目标是让您熟悉 Azure Functions 以及在使用它时可以实施的最佳实践。值得一提的是，使用 Azure Functions 是一个很好的选择，可以加速您的开发，为您提供无服务器实现的替代方案。借助它们，您可以更快地部署 API，启用由定时器触发的服务，甚至通过接收存储事件来触发流程。

在本章中，我们将涵盖以下主题：

+   了解 Azure Functions 应用程序

+   使用 C#编程 Azure Functions

+   维护 Azure Functions

+   用例-实现 Azure Functions 发送电子邮件

通过本章结束时，您将了解如何使用 C#中的 Azure Functions 来加快开发周期。

# 技术要求

本章要求您具备以下条件：

+   Visual Studio 2019 免费社区版或更高版本，所有 Azure 工具都已安装。

+   一个免费的 Azure 账户。*第一章*的*创建 Azure 账户*部分解释了如何创建。

您可以在[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5/tree/master/ch10`](https://github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5/tree/master/ch10)找到本章的示例代码。

# 了解 Azure Functions 应用程序

Azure Functions 应用程序是 Azure PaaS，您可以在其中构建代码片段（函数），并将它们连接到您的应用程序，并使用触发器启动它们。这个概念非常简单-您可以用您喜欢的语言编写函数，并决定启动它的触发器。您可以在系统中编写尽可能多的函数。有些情况下，整个系统都是用函数编写的。

创建必要环境的步骤与创建函数本身的步骤一样简单。以下屏幕截图显示了创建环境时必须决定的参数。在 Azure 中选择**创建资源**并按**Function App**进行筛选，然后单击**创建**按钮，您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_01.png)

图 10.1：创建 Azure 函数

在创建 Azure Functions 环境时，有几个关键点需要考虑。随着时间的推移，运行函数的可能性不断增加，编程语言选项和发布样式也在不断增加。我们最重要的配置之一是托管计划，这是您运行函数的地方。托管计划有三个选项：消耗（无服务器）、高级和应用服务计划。现在让我们来谈谈这些。

## 消耗计划

如果您选择消耗计划，您的函数只会在执行时消耗资源。这意味着只有在函数运行时才会收费。可扩展性和内存资源将由 Azure 自动管理。这确实是我们所说的无服务器。

在编写此计划中的函数时，我们需要注意超时。默认情况下，函数将在 5 分钟后超时。您可以使用`host.json`文件中的`functionTimeout`参数更改超时值。最大值为 10 分钟。

当您选择消耗计划时，您将被收取费用的方式取决于您执行的内容、执行时间和内存使用情况。有关更多信息，请访问[`azure.microsoft.com/en-us/pricing/details/functions/`](https://azure.microsoft.com/en-us/pricing/details/functions/)。

请注意，当您的环境中没有应用服务，并且您正在运行低周期性的函数时，这可能是一个不错的选择。另一方面，如果您需要持续处理，您可能需要考虑应用服务计划。

## 高级计划

根据您使用函数的方式，特别是如果它们需要持续运行或几乎持续运行，或者如果某些函数执行时间超过 10 分钟，您可能需要考虑使用高级计划。此外，您可能需要将函数连接到 VNET/VPN 环境，在这种情况下，您将被迫在此计划中运行。

您可能还需要比消耗计划提供的更多 CPU 或内存选项。高级计划为您提供了一个核心、两个核心和四个核心的实例选项。

值得一提的是，即使您有无限的时间来运行函数，如果您决定使用 HTTP 触发函数，响应请求的最大允许时间为 230 秒。这个限制的原因与 Azure 负载均衡器有关。在这种情况下，您可能需要重新设计您的解决方案，以符合 Microsoft 设置的最佳实践（[`docs.microsoft.com/en-us/azure/azure-functions/functions-best-practices`](https://docs.microsoft.com/en-us/azure/azure-functions/functions-best-practices)）。

## 应用服务计划

应用服务计划是您在创建 Azure 函数应用时可以选择的选项之一。以下是一些（由 Microsoft 建议的）您应该使用应用服务计划而不是消耗计划来维护函数的原因列表：

+   您可以使用未充分利用的现有应用服务实例。

+   您想在自定义镜像上运行函数应用。

在应用服务计划方案中，`functionTimeout`值根据 Azure 函数运行时版本而变化。但是，该值至少为 30 分钟。您可以在[`docs.microsoft.com/en-us/azure/azure-functions/functions-scale#timeout`](https://docs.microsoft.com/en-us/azure/azure-functions/functions-scale#timeout)找到每个消耗计划中超时的表格比较。

# 使用 C#编程 Azure 函数

在本节中，您将学习如何创建 Azure 函数。值得一提的是，有几种使用 C#创建函数的方法。第一种方法是在 Azure 门户中创建函数并在其中开发它们。为此，让我们假设您已经创建了一个 Azure 函数应用，并且配置与本章开头的屏幕截图类似。

通过选择创建的资源并导航到**函数**菜单，您将能够在此环境中**添加**新的函数，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_02.png)

图 10.2：添加函数

在这里，您需要决定要使用的触发器类型来启动执行。最常用的是**HTTP 触发器**和**定时器触发器**。第一个可以创建一个将触发函数的 HTTP API。第二个意味着函数将由根据您的决定设置的定时器触发。

当您决定要使用的触发器时，您必须为函数命名。根据您决定的触发器，您将不得不设置一些参数。例如，HTTP 触发器要求您设置授权级别。有三个选项可用，即**函数**、**匿名**和**管理员**：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_03.png)

图 10.3：配置 HTTP 函数

值得一提的是，本书并未涵盖在构建函数时可用的所有选项。作为软件架构师，您应该了解 Azure 在函数方面提供了良好的无服务器架构服务。这在几种情况下都可能很有用。这在*第四章*，*决定最佳基于云的解决方案*中有更详细的讨论。

其结果如下。请注意，Azure 提供了一个编辑器，允许我们运行代码，检查日志，并测试我们创建的函数。这是一个用于测试和编写基本函数的良好界面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_04.png)

图 10.4：HTTP 函数环境

然而，如果您想创建更复杂的函数，您可能需要一个更复杂的环境，以便您可以更有效地编写和调试它们。这就是 Visual Studio Azure 函数项目可以帮助您的地方。此外，使用 Visual Studio 执行函数的开发将使您朝着为函数使用源代码控制和 CI/CD 的方向迈进。

在 Visual Studio 中，您可以通过转到**创建新项目**来创建一个专用于 Azure 函数的项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_05.png)

图 10.5：在 Visual Studio 2019 中创建 Azure 函数项目

提交项目后，Visual Studio 将询问您正在使用的触发器类型以及您的函数将在哪个 Azure 版本上运行：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_06.png)

图 10.6：创建新的 Azure 函数应用程序

值得一提的是，Azure 函数支持不同的平台和编程语言。在撰写本文时，Azure 函数有三个运行时版本，C#可以在所有这些版本中运行。第一个版本兼容.NET Framework 4.7。在第二个版本中，您可以创建在.NET Core 2.2 上运行的函数。在第三个版本中，您将能够运行.NET Core 3.1 和.NET 5。

作为软件架构师，您必须牢记代码的可重用性。在这种情况下，您应该注意选择在哪个版本的 Azure 函数项目中构建您的函数。然而，建议您始终使用最新版本的运行时，一旦它获得一般可用性状态。

默认情况下，生成的代码与在 Azure 门户中创建 Azure 函数时生成的代码相似：

```cs
using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
namespace FunctionAppSample
{
    public static class FunctionTrigger
    {
        [FunctionName("FunctionTrigger")]
        public static void Run([TimerTrigger("0 */5 * * * *")]
            TimerInfo myTimer, ILogger log)
        {
             log.LogInformation($"C# Timer trigger function " +
                 $"executed at: {DateTime.Now}");
        }
    }
} 
```

发布方法遵循与我们在《第一章》*理解软件架构的重要性*中描述的 Web 应用程序的发布过程相同的步骤。然而，建议始终使用 CI/CD 管道，正如我们将在《第二十章》*理解 DevOps 原则*中描述的那样。

## 列出 Azure 函数模板

Azure 门户中有几个模板可供您使用以创建 Azure 函数。您可以不断更新可选择的模板数量。以下只是其中的一些：

+   Blob 触发器：您可能希望在文件上传到 blob 存储时立即处理某些内容。这可以是 Azure 函数的一个很好的用例。

+   Cosmos DB 触发器：您可能希望将到达 Cosmos DB 数据库的数据与处理方法同步。Cosmos DB 在《第九章》*如何选择云中的数据存储*中有详细讨论。

+   事件网格触发器：这是管理 Azure 事件的一种好方法。函数可以被触发以便它们管理每个事件。

+   事件中心触发器：使用此触发器，您可以构建与将数据发送到 Azure 事件中心的任何系统相关联的函数。

+   HTTP 触发器：此触发器对于构建无服务器 API 和 Web 应用程序事件非常有用。

+   IoT Hub 触发器：当您的应用程序通过 IoT Hub 与设备连接时，您可以在设备中收到新事件时使用此触发器。

+   队列触发器：您可以使用函数作为服务解决方案来处理队列处理。

+   服务总线队列触发器：这是另一个可以成为函数触发器的消息传递服务。Azure 服务总线将在《第十一章》*设计模式和.NET 5 实现*中进行更详细的介绍。

+   定时器触发器：这通常与函数一起使用，您可以在其中指定时间触发器，以便可以持续处理来自系统的数据。

# 维护 Azure 函数

创建和编程函数后，您需要监视和维护它。为此，您可以使用各种工具，所有这些工具都可以在 Azure 门户中找到。这些工具将帮助您解决问题，因为您将能够收集大量信息。

在监视函数时的第一个选项是在 Azure 门户中的 Azure 函数界面内使用“监视”菜单。在那里，您将能够检查所有函数执行，包括成功的结果和失败的结果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_07.png)

图 10.7：监控函数

任何结果可用需要大约 5 分钟。网格中显示的日期是 UTC 时间。

通过单击“在 Application Insights 中运行查询”，相同的界面允许您连接到此工具。这将带您进入一个几乎无限的选项世界，您可以使用它来分析您的函数数据。Application Insights 是当今最好的“应用程序性能管理”（APM）系统之一：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_08.png)

图 10.8：使用 Application Insights 进行监控

除了查询界面，您还可以使用 Azure 门户中的 Insights 界面检查函数的所有性能问题。在那里，您可以分析和过滤已收到的所有请求，并检查它们的性能和依赖关系。当您的一个端点发生异常时，您还可以触发警报：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_09.png)

图 10.9：使用 Application Insights 实时指标监控

作为软件架构师，您会发现这个工具对您的项目是一个很好的日常助手。值得一提的是，Application Insights 还适用于其他几个 Azure 服务，例如 Web 应用程序和虚拟机。这意味着您可以使用 Azure 提供的出色功能来监视系统的健康状况并进行维护。

# 用例 - 实现 Azure 函数发送电子邮件

在这里，我们将使用我们之前描述的 Azure 组件的子集。WWTravelClub 的用例提出了该服务的全球实施，并且有可能该服务将需要不同的架构设计来应对我们在*第一章*“理解软件架构的重要性”中描述的所有性能关键点。

如果您回顾一下在*第一章*“理解软件架构的重要性”中描述的用户故事，您会发现许多需求与通信有关。因此，在解决方案中通常会通过电子邮件提供一些警报。本章的用例将重点介绍如何发送电子邮件。该架构将完全无服务器。

以下图表显示了架构的基本结构。为了给用户带来良好的体验，应用程序发送的所有电子邮件都将以异步方式排队，从而防止系统响应出现显着延迟：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_10.png)

图 10.10：发送电子邮件的架构设计

请注意，没有服务器管理 Azure 函数来对 Azure 队列存储中的消息进行入队或出队操作。这正是我们所说的无服务器。值得一提的是，这种架构不仅限于发送电子邮件 - 它也可以用于处理任何 HTTP`POST`请求。

现在，我们将学习如何在 API 中设置安全性，以便只有经过授权的应用程序可以使用给定的解决方案。

## 第一步 - 创建 Azure 队列存储

在 Azure 门户中创建存储非常简单。让我们来学习如何操作。首先，您需要通过单击 Azure 门户主页上的**创建资源**来创建一个存储账户，并搜索**存储账户**。然后，您可以设置其基本信息，如**存储账户名称**和**位置**。此向导还可以检查有关**网络**和**数据保护**的信息，如下图所示。这些设置有默认值，将覆盖演示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_11.png)

图 10.11：创建 Azure 存储账户

一旦您设置好存储账户，您就可以设置一个队列。您可以通过单击存储账户中的**概述**链接并选择**队列**选项，或者通过存储账户菜单选择**队列**来找到此选项。然后，您将找到一个添加队列的选项（**+队列**），您只需要提供其名称即可：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_12.png)

图 10.12：定义监视电子邮件的队列

创建的队列将在 Azure 门户中为您提供概览。在那里，您将找到您的队列的 URL 并使用 Storage Explorer：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_13.png)

图 10.13：创建的队列

请注意，您还可以使用 Microsoft Azure Storage Explorer 连接到此存储（[`azure.microsoft.com/en-us/features/storage-explorer/`](https://azure.microsoft.com/en-us/features/storage-explorer/)）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_14.png)

图 10.14：使用 Microsoft Azure Storage Explorer 监视队列

如果您没有连接到 Azure 门户，此工具尤其有用。

## 第二步 - 创建发送电子邮件的函数

现在，您可以认真开始编程，通知队列等待发送电子邮件。在这里，我们需要使用 HTTP 触发器。请注意，该函数是一个静态类，可以异步运行。以下代码正在收集来自 HTTP 触发器的请求数据，并将数据插入稍后将处理的队列中：

```cs
public static class SendEmail
{
    [FunctionName(nameof(SendEmail))]
    public static async Task<HttpResponseMessage>RunAsync( [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestMessage req, ILogger log)
    {
        var requestData = await req.Content.ReadAsStringAsync();
        var connectionString = Environment.GetEnvironmentVariable("AzureQueueStorage");
        var storageAccount = CloudStorageAccount.Parse(connectionString);
        var queueClient = storageAccount.CreateCloudQueueClient();
        var messageQueue = queueClient.GetQueueReference("email");
        var message = new CloudQueueMessage(requestData);
        await messageQueue.AddMessageAsync(message);
        log.LogInformation("HTTP trigger from SendEmail function processed a request.");
        var responseObj = new { success = true };
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonConvert.SerializeObject(responseObj), Encoding.UTF8, "application/json"),
         };
    }
} 
```

在某些情况下，您可以尝试避免使用前面代码中指示的队列设置，而是使用队列输出绑定。在[`docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-storage-queue-output?tabs=csharp`](https://docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-storage-queue-output?tabs=)上查看详细信息。

您可以使用诸如 Postman 之类的工具通过运行 Azure Functions 模拟器来测试函数：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_15.png)

图 10.15：Postman 函数测试

结果将出现在 Microsoft Azure Storage Explorer 和 Azure 门户中。在 Azure 门户中，您可以管理每条消息并出列每条消息，甚至清除队列存储：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_16.png)

图 10.16：HTTP 触发器和队列存储测试

## 第三步 - 创建队列触发函数

之后，您可以创建第二个函数。这个函数将由进入队列的数据触发。值得一提的是，对于 Azure Functions v3，您将自动将`Microsoft.Azure.WebJobs.Extensions.Storage`库添加为 NuGet 引用：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_17.png)

图 10.17：创建队列触发

一旦您在`local.settings.json`中设置了连接字符串，您就可以运行这两个函数并使用 Postman 进行测试。不同之处在于，如果第二个函数正在运行，如果您在其开头设置断点，您将检查消息是否已发送：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_10_18.png)

图 10.18：在 Visual Studio 2019 中触发队列

从这一点开始，发送电子邮件的方式将取决于您拥有的邮件选项。您可以决定使用代理或直接连接到您的电子邮件服务器。

以这种方式创建电子邮件服务有几个优势：

+   一旦您的服务已编码并经过测试，您就可以使用它从任何应用程序发送电子邮件。这意味着您的代码可以始终被重用。

+   使用此服务的应用程序不会因为在 HTTP 服务中发布异步优势而停止发送电子邮件。

+   不需要池化队列来检查数据是否准备好进行处理。

最后，队列进程并发运行，这在大多数情况下提供了更好的体验。可以通过在`host.json`中设置一些属性来关闭它。所有这些选项都可以在本章末尾的*进一步阅读*部分找到。

# 总结

在本章中，我们看了一些使用无服务器 Azure 函数开发功能的优势。您可以将其用作检查 Azure Functions 中可用的不同类型触发器和计划如何监视它们的指南。我们还看到了如何编程和维护 Azure 函数。最后，我们看了一个架构示例，其中您可以连接多个函数以避免池化数据并实现并发处理。

在下一章中，我们将分析设计模式的概念，了解它们为什么如此有用，并了解一些常见模式。

# 问题

1.  Azure 函数是什么？

1.  Azure 函数的编程选项是什么？

1.  可以与 Azure 函数一起使用的计划是什么？

1.  如何使用 Visual Studio 部署 Azure 函数？

1.  可以使用哪些触发器来开发 Azure 函数？

1.  Azure Functions v1、v2 和 v3 有什么区别？

1.  应用程序洞察如何帮助我们维护和监视 Azure 函数？

# 进一步阅读

如果您想了解有关创建 Azure 函数的更多信息，请查看以下链接：

+   Azure 函数的规模和托管：[`docs.microsoft.com/en-us/azure/azure-functions/functions-scale`](https://docs.microsoft.com/en-us/azure/azure-functions/functions-scale)

+   *Azure Functions – Essentials [Video]*，作者 Praveen Kumar Sreeram：[`www.packtpub.com/virtualization-and-cloud/azure-functions-essentials-video`](https://www.packtpub.com/virtualization-and-cloud/azure-functions-essentials-video)

+   Azure Functions 运行时概述：[`docs.microsoft.com/en-us/azure/azure-functions/functions-versions`](https://docs.microsoft.com/en-us/azure/azure-functions/functions-versions)

+   Azure 事件网格概述：[`azure.microsoft.com/en-us/resources/videos/an-overview-of-azure-event-grid/`](https://azure.microsoft.com/en-us/resources/videos/an-overview-of-azure-event-grid/)

+   Azure Functions 的定时器触发器：[`docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer`](https://docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer)

+   书籍*Azure for Architects*中的应用程序洞察部分，作者 Ritesh Modi：[`subscription.packtpub.com/book/virtualization_and_cloud/9781788397391/12/ch12lvl1sec95/application-insights`](https://subscription.packtpub.com/book/virtualization_and_cloud/9781788397391/12/ch12lvl1sec95/appli)

+   使用书籍*Azure Serverless Computing Cookbook*中的应用程序洞察部分监视 Azure 函数，作者 Praveen Kumar Sreeram：[`subscription.packtpub.com/book/virtualization_and_cloud/9781788390828/6/06lvl1sec34/monitoring-azure-functions-using-application-insights`](https://subscription.packtpub.com/book/virtualization_and_cloud/9781788390828/6/06lvl1sec34/monitori)

+   使用.NET 开始使用 Azure 队列存储：[`docs.microsoft.com/en-us/azure/storage/queues/storage-dotnet-how-to-use-queues`](https://docs.microsoft.com/en-us/azure/storage/queues/storage-dotnet-how-to-use-queues)

+   Azure Functions 触发器和绑定概念：[`docs.microsoft.com/en-us/azure/azure-functions/functions-triggers-bindings`](https://docs.microsoft.com/en-us/azure/azure-functions/functions-triggers-bindings)

+   Azure 函数的 Azure 队列存储绑定：[`docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-storage-queue`](https://docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-storage-queue)


# 第十一章：设计模式和.NET 5 实现

设计模式可以被定义为常见问题的现成架构解决方案，在软件开发过程中遇到这些问题是必不可少的。它们对于理解.NET Core 架构至关重要，并且对于解决我们在设计任何软件时面临的普通问题非常有用。在本章中，我们将看一些设计模式的实现。值得一提的是，本书并未解释我们可以使用的所有已知模式。重点在于解释学习和应用它们的重要性。

在本章中，我们将涵盖以下主题：

+   理解设计模式及其目的

+   了解.NET 5 中可用的设计模式

在本章结束时，您将学习到一些可以用设计模式实现的**WWTravelClub**的用例。

# 技术要求

要完成本章，您需要免费的 Visual Studio 2019 社区版或更高版本，安装了所有数据库工具，以及一个免费的 Azure 账户。*第一章*的*理解软件架构的重要性*中的*创建 Azure 账户*小节解释了如何创建账户。

您可以在[`github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5`](https://github.com/PacktPublishing/Software-Architecture-with-C-9-and-.NET-5)找到本章的示例代码。

# 理解设计模式及其目的

决定系统设计是具有挑战性的，与此任务相关的责任是巨大的。作为软件架构师，我们必须始终牢记，诸如良好的可重用性、良好的性能和良好的可维护性等功能对于提供良好的解决方案至关重要。这就是设计模式帮助并加速设计过程的地方。

正如我们之前提到的，设计模式是已经讨论和定义的解决常见软件架构问题的解决方案。这种方法在《设计模式-可复用面向对象软件的元素》一书发布后变得越来越受欢迎，**四人帮**（**GoF**）将这些模式分为三种类型：创建型、结构型和行为型。

稍后，Bob 大叔向开发者社区介绍了 SOLID 原则，使我们有机会有效地组织每个系统的函数和数据结构。SOLID 设计原则指示软件组件应该如何设计和连接。值得一提的是，与 GoF 提出的设计模式相比，SOLID 原则并不提供代码配方。相反，它们给出了在设计解决方案时要遵循的基本原则，保持软件结构的强大和可靠。它们可以被定义如下：

+   **单一职责原则**：一个模块或函数应该负责一个单一的目的

+   **开闭原则**：软件构件应该对扩展开放，但对修改关闭

+   **里氏替换原则**：当你用一个由原始对象的超类型定义的另一个组件替换一个组件时，程序的行为需要保持不变

+   **接口隔离原则**：创建庞大的接口会导致依赖关系的发生，而在构建具体对象时，这对系统架构是有害的

+   **依赖倒置原则**：最灵活的系统是那些对象依赖仅指向抽象的系统

随着技术和软件问题的变化，会产生更多的模式。云计算的发展带来了大量模式，所有这些模式都可以在[`docs.microsoft.com/en-us/azure/architecture/patterns/`](https://docs.microsoft.com/en-us/azure/architecture/patterns/)找到。新模式出现的原因与我们在开发新解决方案时面临的挑战有关。今天，可用性、数据管理、消息传递、监控、性能、可伸缩性、弹性和安全性是我们在交付云解决方案时必须处理的方面。

你应该始终考虑使用设计模式的原因非常简单——作为软件架构师，你不能花时间重新发明轮子。然而，使用和理解它们的另一个很好的原因是：你会发现许多这些模式已经在.NET 5 中实现了。

在接下来的几个小节中，我们将介绍一些最著名的模式。然而，本章的目的是让你知道它们的存在，并且需要学习它们，以便加速和简化你的项目。此外，每个模式都将以 C#代码片段的形式呈现，以便你可以在你的项目中轻松实现它们。

## 建造者模式

有些情况下，你会有一个由于其配置而具有不同行为的复杂对象。你可能希望将该对象的配置与其使用分离，使用已经构建好的自定义配置。这样，你就有了正在构建的实例的不同表示。这就是你应该使用建造者模式的地方。

以下的类图显示了为本书使用案例中的场景实现的模式。这个设计选择背后的想法是简化对 WWTravelClub 房间的描述方式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_01.png)

图 11.1：建造者模式

如下面的代码所示，这个代码是以一种不在主程序中设置实例的配置的方式实现的。相反，你只需使用`Build()`方法构建对象。这个例子模拟了在 WWTravelClub 中创建不同房间样式（单人房和家庭房）的过程：

```cs
using DesignPatternsSample.BuilderSample;
using System;
namespace DesignPatternsSample
{
    class Program
    {
        static void Main()
        {
          #region Builder Sample
          Console.WriteLine("Builder Sample");
          var simpleRoom = new SimpleRoomBuilder().Build();
          simpleRoom.Describe();

          var familyRoom = new FamilyRoomBuilder().Build();
          familyRoom.Describe();
          #endregion
          Console.ReadKey();
        }
    }
} 
```

这个实现的结果非常简单，但澄清了为什么需要实现模式：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_02.png)

图 11.2：建造者模式示例结果

一旦你有了实现，进化这段代码就变得更简单、更容易。例如，如果你需要构建不同风格的房间，你只需为该类型的房间创建一个新的建造者，然后你就可以使用它了。

这个实现变得非常简单的原因与在`Room`类中使用链式方法有关：

```cs
 public class Room
    {
        private readonly string _name;
        private bool wiFiFreeOfCharge;
        private int numberOfBeds;
        private bool balconyAvailable;
        public Room(string name)
        {
            _name = name;
        }
        public Room WithBalcony()
        {
            balconyAvailable = true;
            return this;
        }
        public Room WithBed(int numberOfBeds)
        {
            this.numberOfBeds = numberOfBeds;
            return this;
        }
        public Room WithWiFi()
        {
            wiFiFreeOfCharge = true;
            return this;
        }
    ...
    } 
```

幸运的是，如果需要增加产品的配置设置，之前使用的所有具体类都将在建造者接口中定义并存储在那里，以便你可以轻松更新它们。

我们还将在.NET 5 中看到建造者模式的一个很好的实现，在*了解.NET 5 中可用的设计模式*部分。在那里，你将能够了解如何使用`HostBuilder`实现了通用主机。

## 工厂模式

工厂模式在有多个来自相同抽象的对象，并且在编码开始时不知道需要创建哪个对象的情况下非常有用。这意味着你将不得不根据特定的配置或软件当前所处的位置来创建实例。

例如，让我们看看 WWTravelClub 示例。在这里，有一个用户故事描述了该应用程序将有来自世界各地的客户支付他们的旅行。然而，在现实世界中，每个国家都有不同的付款服务可用。每个国家的支付过程都类似，但该系统将有多个可用的付款服务。简化此付款实现的一种好方法是使用工厂模式。以下图表显示了其架构实现的基本思想：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_03.png)

图 11.3：工厂模式

请注意，由于您有一个描述应用程序的付款服务的接口，您可以使用工厂模式根据可用的服务更改具体类：

```cs
static void Main()
{
    #region Factory Sample
    ProcessCharging(PaymentServiceFactory.ServicesAvailable.Brazilian,
        "gabriel@sample.com", 178.90f, EnumChargingOptions.CreditCard);

    ProcessCharging(PaymentServiceFactory.ServicesAvailable.Italian,
        "francesco@sample.com", 188.70f, EnumChargingOptions.DebitCard);
    #endregion
    Console.ReadKey();
}
private static void ProcessCharging
    (PaymentServiceFactory.ServicesAvailable serviceToCharge,
    string emailToCharge, float moneyToCharge, 
    EnumChargingOptions optionToCharge)
{
    PaymentServiceFactory factory = new PaymentServiceFactory();
    var service = factory.Create(serviceToCharge);
    service.EmailToCharge = emailToCharge;
    service.MoneyToCharge = moneyToCharge;
    service.OptionToCharge = optionToCharge;
    service.ProcessCharging();
} 
```

再次，由于实现的模式，服务的使用变得更加简单。如果您必须在真实世界的应用程序中使用此代码，您可以通过在工厂模式中定义所需的服务来更改实例的行为。

## 单例模式

当您在应用程序中实现单例时，您将在整个解决方案中实现对象的单个实例。这可以被认为是每个应用程序中最常用的模式之一。原因很简单-有许多用例需要一些类只有一个实例。单例通过提供比全局变量更好的解决方案来解决这个问题。

在单例模式中，类负责创建和提供应用程序将使用的单个对象。换句话说，单例类创建一个单一实例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_04.png)

图 11.4：单例模式

为此，创建的对象是`static`，并在静态属性或方法中提供。以下代码实现了具有`Message`属性和`Print()`方法的单例模式：

```cs
public sealed class SingletonDemo
{
    #region This is the Singleton definition
    private static SingletonDemo _instance;
    public static SingletonDemo Current => _instance ??= new 
        SingletonDemo();
    #endregion
    public string Message { get; set; }
    public void Print()
    {
        Console.WriteLine(Message);
    }
} 
```

它的使用很简单-每次需要使用单例对象时，只需调用静态属性：

```cs
SingletonDemo.Current.Message = "This text will be printed by " +
  "the singleton.";
SingletonDemo.Current.Print(); 
```

您可能使用此模式的一个场景是需要以可以轻松从解决方案的任何地方访问的方式提供应用程序配置。例如，假设您有一些配置参数存储在应用程序需要在多个决策点查询的表中。您可以创建一个单例类来帮助您，而不是直接查询配置表。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_05.png)

图 11.5：单例模式的使用

此外，您需要在此单例中实现缓存，从而提高系统的性能，因为您可以决定系统是否每次需要时都会检查数据库中的每个配置，还是使用缓存。以下屏幕截图显示了缓存的实现，其中配置每 5 秒加载一次。在这种情况下读取的参数只是一个随机数：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_06.png)

图 11.6：单例模式内部的缓存实现

这对应用程序的性能非常有利。此外，在代码中的多个地方使用参数更简单，因为您不必在代码的各处创建配置实例。

值得一提的是，由于.NET 5 中的依赖注入实现，单例模式的使用变得不太常见，因为您可以设置依赖注入来处理您的单例对象。我们将在本章的后面部分介绍.NET 5 中的依赖注入。

## 代理模式

代理模式用于在需要提供控制对另一个对象访问的对象时使用。为什么要这样做的最大原因之一与创建被控制对象的成本有关。例如，如果被控制的对象创建时间过长或消耗过多内存，可以使用代理来确保只有在需要时才会创建对象的大部分。

以下类图是**代理**模式实现从**Room**加载图片的示例，但只有在请求时：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_07.png)

图 11.7：代理模式实现

该代理的客户端将请求其创建。在这里，代理只会从真实对象中收集基本信息（`Id`，`FileName`和`Tags`），而不会查询`PictureData`。当请求`PictureData`时，代理将加载它：

```cs
static void Main()
{
    Console.WriteLine("Proxy Sample");
    ExecuteProxySample(new ProxyRoomPicture());
}
private static void ExecuteProxySample(IRoomPicture roomPicture)
{
    Console.WriteLine($"Picture Id: {roomPicture.Id}");
    Console.WriteLine($"Picture FileName: {roomPicture.FileName}");
    Console.WriteLine($"Tags: {string.Join(";", roomPicture.Tags)}");
    Console.WriteLine($"1st call: Picture Data");
    Console.WriteLine($"Image: {roomPicture.PictureData}");
    Console.WriteLine($"2nd call: Picture Data");
    Console.WriteLine($"Image: {roomPicture.PictureData}");
} 
```

如果再次请求`PictureData`，由于图像数据已经就位，代理将保证不会重复加载图像。以下截图显示了运行上述代码的结果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_08.png)

图 11.8：代理模式结果

这种技术也可以称为另一个众所周知的模式：**惰性加载**。事实上，代理模式是实现惰性加载的一种方式。实现惰性加载的另一种方法是使用`Lazy<T>`类型。例如，在 Entity Framework Core 5 中，正如*第八章*，*在 C#中与数据交互-Entity Framework Core*中讨论的那样，你可以使用代理打开惰性加载。你可以在[`docs.microsoft.com/en-us/ef/core/querying/related-data#lazy-loading`](https://docs.microsoft.com/en-us/ef/core/querying/related-data#lazy-loading)找到更多信息。

## 命令模式

有许多情况下，你需要执行一个会影响对象行为的**命令**。命令模式可以通过封装这种请求到一个对象中来帮助你。该模式还描述了如何处理请求的撤销/重做支持。

例如，让我们想象一下，在 WWTravelClub 网站上，用户可能有能力通过指定他们喜欢、不喜欢，甚至是喜爱他们的体验来评估套餐。

以下类图是一个示例，可以实现使用命令模式创建此评分系统：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_09.png)

图 11.9：命令模式

注意这种模式的工作方式——如果你需要一个不同的命令，比如`Hate`，你不需要更改使用命令的代码和类。`Undo`方法可以以类似的方式添加到`Redo`方法。这方面的完整代码示例可以在本书的 GitHub 存储库中找到。

还值得一提的是，ASP.NET Core MVC 使用命令模式来处理其`IActionResult`层次结构。此外，*第十二章*，*理解软件解决方案中的不同领域*中描述的业务操作将使用该模式来执行业务规则。

## 发布者/订阅者模式

将对象的信息提供给一组其他对象在所有应用程序中都很常见。当有大量组件（订阅者）将接收包含对象发送的信息的消息时，发布者/订阅者模式几乎是必不可少的。

这里的概念非常简单易懂，并且在下图中有所展示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_10.png)

图 11.10：发布者/订阅者示例案例

当你有无数个可能的订阅者时，将广播信息的组件与消费信息的组件解耦是至关重要的。发布者/订阅者模式为我们做到了这一点。

实施这种模式是复杂的，因为分发环境并不是一个简单的任务。因此，建议您考虑已经存在的技术来实现连接输入通道和输出通道的消息代理，而不是从头开始构建它。Azure Service Bus 是这种模式的可靠实现，所以你只需要连接到它。

我们在*第五章*中提到的 RabbitMQ，*将微服务架构应用于企业应用程序*，是另一个可以用来实现消息代理的服务，但它是该模式的较低级别实现，并且需要进行多个相关任务，例如手动编码重试以处理错误。

## 依赖注入模式

依赖注入模式被认为是实现依赖反转原则的一种好方法。一个有用的副作用是，它强制任何实现遵循所有其他 SOLID 原则。

这个概念非常简单。您只需要定义它们的依赖关系，声明它们的接口，并通过**注入**启用对象的接收，而不是创建组件所依赖的对象的实例。

有三种方法可以执行依赖注入：

+   使用类的构造函数接收对象

+   标记一些类属性以接收对象

+   定义一个具有注入所有必要组件的方法的接口

以下图表显示了依赖注入模式的实现：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/sw-arch-cs9-dn5/img/B16756_11_11.png)

图 11.11：依赖注入模式

除此之外，依赖注入还可以与**控制反转**（**IoC**）容器一起使用。该容器在被要求时自动注入依赖项。市场上有几个 IoC 容器框架可用，但是在.NET Core 中，无需使用第三方软件，因为它包含一组库来解决`Microsoft.Extensions.DependencyInjection`命名空间中的问题。

这个 IoC 容器负责创建和处理被请求的对象。依赖注入的实现基于构造函数类型。对于被注入组件的生命周期，有三个选项：

+   **瞬态**：每次请求时都会创建对象。

+   **作用域**：为应用程序中定义的每个作用域创建对象。在 Web 应用程序中，**作用域**是通过 Web 请求标识的。

+   **单例**：每个对象具有相同的应用程序生命周期，因此重用单个对象来为给定类型的所有请求提供服务。如果您的对象包含状态，则不应使用此对象，除非它是线程安全的。

您将如何使用这些选项取决于您正在开发的项目的业务规则。这也取决于您将如何注册应用程序的服务。在决定正确的选项时，您需要小心，因为应用程序的行为将根据您注入的对象类型而改变。

# 了解.NET 5 中可用的设计模式

在前面的部分中，我们发现 C#允许我们实现任何模式。 .NET 5 在其 SDK 中提供了许多实现，遵循我们讨论过的所有模式，例如 Entity Framework Core 代理延迟加载。自.NET Core 2.1 以来可用的另一个很好的例子是.NET 通用主机。

在*第十五章*中，*介绍 ASP.NET Core MVC*，我们将详细介绍.NET 5 中 Web 应用程序可用的托管。这个 Web 主机在应用程序的启动和生命周期管理方面对我们很有帮助。.NET 通用主机的想法是为不需要 HTTP 实现的应用程序启用这种模式。通过这个通用主机，任何.NET Core 程序都可以有一个启动类，我们可以在其中配置依赖注入引擎。这对于创建多服务应用程序非常有用。

您可以在[`docs.microsoft.com/en-us/aspnet/core/fundamentals/host/generic-host`](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/host/generic-host)找到更多关于.NET 通用主机的信息，其中包含一些示例代码，并且是微软目前的推荐。GitHub 存储库中提供的代码更简单，但它侧重于创建一个可以运行监视服务的控制台应用程序。这种方法的伟大之处在于控制台应用程序的设置方式，生成器配置了应用程序提供的服务，以及日志记录的管理方式。

这在以下代码中显示：

```cs
public static void Main()
{
    var host = new HostBuilder()
        .ConfigureServices((hostContext, services) =>
        {
            services.AddHostedService<HostedService>();
            services.AddHostedService<MonitoringService>();
        })
        .ConfigureLogging((hostContext, configLogging) =>
        {
            configLogging.AddConsole();
        })
        .Build();
    host.Run();
    Console.WriteLine("Host has terminated. Press any key to finish the App.");
    Console.ReadKey();
} 
```

上述代码让我们了解了.NET Core 如何使用设计模式。使用生成器模式，.NET 通用主机允许您设置将作为服务注入的类。除此之外，生成器模式还帮助您配置其他一些功能，例如日志的显示/存储方式。此配置允许服务将`ILogger<out TCategoryName>`对象注入到任何实例中。

# 总结

在本章中，我们了解了为什么设计模式有助于系统部分的可维护性和可重用性。我们还看了一些典型的用例和代码片段，您可以在项目中使用。最后，我们介绍了.NET 通用主机，这是.NET 使用设计模式实现代码重用和执行最佳实践的一个很好的例子。

所有这些内容都将帮助您在设计新软件或维护现有软件时，因为设计模式已经是软件开发中一些现实问题的已知解决方案。

在下一章中，我们将介绍领域驱动设计方法。我们还将学习如何使用 SOLID 设计原则，以便将不同的领域映射到我们的软件解决方案中。

# 问题

1.  什么是设计模式？

1.  设计模式和设计原则之间有什么区别？

1.  何时实现生成器模式是一个好主意？

1.  何时实现工厂模式是一个好主意？

1.  何时实现单例模式是一个好主意？

1.  何时实现代理模式是一个好主意？

1.  何时实现命令模式是一个好主意？

1.  何时实现发布者/订阅者模式是一个好主意？

1.  何时实现依赖注入模式是一个好主意？

# 进一步阅读

以下是一些书籍和网站，您可以在其中找到有关本章内容的更多信息：

+   *Clean Architecture: A Craftsman's Guide to Software Structure and Design*，Martin, Robert C., Pearson Education, 2018.

+   *Design Patterns: Elements of Reusable Object-Oriented Software*，Erica Gamma 等人，Addison-Wesley，1994 年。

+   *Design Principles and Design Patterns*，Martin, Robert C., 2000.

+   如果您需要获取有关设计模式和架构原则的更多信息，请查看以下链接：

+   [`www.packtpub.com/application-development/design-patterns-using-c-and-net-core-video`](https://www.packtpub.com/application-development/design-patterns-using-c-and-net-core-video)

+   [`docs.microsoft.com/en-us/dotnet/standard/modern-web-apps-azure-architecture/architectural-principles`](https://docs.microsoft.com/en-us/dotnet/standard/modern-web-apps-azure-architecture/architectural-pr)

+   如果您想查看特定的云设计模式，可以在以下链接找到：

+   [`docs.microsoft.com/en-us/azure/architecture/patterns/`](https://docs.microsoft.com/en-us/azure/architecture/patterns/)

+   如果您想更好地理解通用主机的概念，请访问此链接：

+   https://docs.microsoft.com/en-us/aspnet/core/fundamentals/host/generic-host

+   在此链接中有关于服务总线消息传递的非常好的解释：

+   [`docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-dotnet-how-to-use-topics-subscriptions`](https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-dotnet-how-to-use-topics-su)

+   你可以通过查看这些链接来了解更多关于依赖注入的信息：

+   [`docs.microsoft.com/en-us/aspnet/core/fundamentals/dependency-injection`](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/dependency-injection)

+   [`www.martinfowler.com/articles/injection.html`](https://www.martinfowler.com/articles/injection.html)
