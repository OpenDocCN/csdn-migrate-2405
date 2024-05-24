# PHP7 编程蓝图（一）

> 原文：[`zh.annas-archive.org/md5/27faa03af47783c6370aa5ff8894925f`](https://zh.annas-archive.org/md5/27faa03af47783c6370aa5ff8894925f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

PHP 是开发 Web 应用程序的优秀语言。它本质上是一种服务器端脚本语言，也用于通用编程。PHP 7 是最新版本，它提供了主要的向后兼容性断裂，并专注于提供改进的性能和速度。随着对高性能的需求增加，这个最新版本包含了构建高效应用程序所需的一切。PHP 7 提供了改进的引擎执行、更好的内存使用以及一套更好的工具，使您能够通过多线程 Web 服务器在低成本硬件和服务器上维护网站的高流量。

# 本书涵盖内容

第一章，创建用户配置文件系统并使用 Null Coalesce 运算符，我们将发现新的 PHP 7 功能，并构建用于存储用户配置文件的应用程序。

第二章，构建数据库类和简单购物车，我们将创建一个简单的数据库层库，帮助我们访问我们的数据库。我们将介绍一些使我们的查询安全的技巧，以及如何使用 PHP 7 使我们的编码更简单、更简洁。

第三章，构建社交通讯服务，我们将构建一个社交通讯服务，用户可以使用其社交登录进行注册，并允许他们注册到通讯服务。我们还将为管理通讯服务创建一个简单的管理员系统。

第四章，使用 Elasticsearch 构建具有搜索功能的简单博客，您将学习如何创建一个博客系统，尝试使用 Elasticsearch 以及如何在您的代码中应用它。此外，您还将学习如何创建一个简单的博客应用程序并将数据存储到 MySQL 中。

第五章，创建 RESTful Web 服务，向您展示如何创建一个可用于管理用户配置文件的 RESTful Web 服务。该服务将使用 Slim 微框架实现，并使用 MongoDB 数据库进行持久化。本章还涵盖了 RESTful Web 服务的基础知识，最重要的是常见的 HTTP 请求和响应方法、PSR-7 标准以及 PHP 7 的新 mongodb 扩展。

第六章，构建聊天应用程序，描述了使用 WebSockets 实现实时聊天应用程序。您将学习如何使用 Ratchet 框架构建独立的 WebSocket 和 HTTP 服务器，并如何在 JavaScript 客户端应用程序中连接到 WebSocket 服务器。我们还将讨论如何为 WebSocket 应用程序实现身份验证以及如何在生产环境中部署它们。

第七章，构建异步微服务架构，涵盖了（小型）微服务架构的实现。在本章中，您将使用 ZeroMQ 而不是 RESTful Web 服务进行网络通信，这是一种专注于异步性、松散耦合和高性能的替代通信协议。

第八章，为自定义语言构建解析器和解释器，描述了如何使用 PHP-PEG 库定义语法并实现自定义表达式语言的解析器，该语言可用于向企业应用程序添加最终用户开发功能。

第九章，PHP 中的 Reactive 扩展，我们将研究 PHP 的 Reactive 扩展库，并尝试构建一个简单的定时应用程序。

# 本书所需内容

您需要从官方 PHP 网站下载并安装 PHP 7。您还需要安装一个 Web 服务器，如 Apache 或 Nginx，并配置为默认运行 PHP 7。

如果您对虚拟机有经验，还可以使用 Docker 容器和/或 Vagrant 来构建一个安装了 PHP 7 的环境。

# 这本书适合谁

这本书是为网页开发人员、PHP 顾问以及任何正在使用 PHP 进行多个项目的人准备的。假定具有 PHP 编程的基本知识。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些样式的示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名会显示如下：“让我们创建一个简单的`UserProfile`类。”

一段代码被设置如下：

```php
function fetch_one($id) { 
  $link = mysqli_connect(''); 
  $query = "SELECT * from ". $this->table . " WHERE `id` =' " .  $id "'"; 
  $results = mysqli_query($link, $query); 
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```php
'credit_card' => $credit_card, 
**'items' => //<all the items and prices>//,** 
'total' => $total,
```

任何命令行输入或输出都以以下方式书写：

```php
 **mysql> source insert_profiles.sql**

```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中出现，就像这样：“只需点击**允许访问**，然后点击**确定**。”

### 注意

警告或重要提示会以这样的框出现。

### 提示

提示和技巧会以这种方式出现。


# 第一章：创建用户配置文件系统并使用空合并运算符

为了开始这一章，让我们来看看 PHP 7 中的新**空合并**。我们还将学习如何构建一个简单的配置文件页面，其中列出了可以单击的用户，并创建一个简单的类似 CRUD 的系统，这将使我们能够注册新用户到系统中，并删除用户以进行封禁。

我们将学习使用 PHP 7 空合并运算符，以便我们可以在有数据时显示数据，或者如果没有数据，只显示一个简单的消息。

让我们创建一个简单的`UserProfile`类。自 PHP 5 以来，创建类的能力就已经可用了。

PHP 中的一个类以`class`开头，后面是类的名称：

```php
class UserProfile { 

  private $table = 'user_profiles'; 

} 

} 

```

我们已经将表格设为私有，并添加了一个`private`变量，我们在其中定义它将与哪个表相关联。

让我们添加两个函数，也称为类中的方法，来简单地从数据库中获取数据：

```php
function fetch_one($id) { 
  $link = mysqli_connect(''); 
  $query = "SELECT * from ". $this->table . " WHERE `id` =' " .  $id "'"; 
  $results = mysqli_query($link, $query); 
} 

function fetch_all() { 
  $link = mysqli_connect('127.0.0.1', 'root','apassword','my_dataabase' ); 
  $query = "SELECT * from ". $this->table . "; 
 $results = mysqli_query($link, $query); 
} 

```

# 空合并运算符

我们可以使用 PHP 7 的空合并运算符来允许我们检查我们的结果是否包含任何内容，或者返回一个我们可以在视图上检查的定义文本，这将负责显示任何数据。

让我们把这个放在一个文件中，其中包含所有的定义语句，并称之为：

```php
//definitions.php 
define('NO_RESULTS_MESSAGE', 'No results found'); 

require('definitions.php'); 
function fetch_all() { 
   ...same lines ... 

   $results = $results ??  NO_RESULTS_MESSAGE; 
   return $message;    
} 

```

在客户端，我们需要设计一个模板来显示用户配置文件的列表。

让我们创建一个基本的 HTML 块，以显示每个配置文件可以是一个`div`元素，其中包含几个列表项元素来输出每个表。

在下面的函数中，我们需要确保所有的值都至少填写了姓名和年龄。然后当函数被调用时，我们只需返回整个字符串：

```php
function profile_template( $name, $age, $country ) { 
 $name = $name ?? null; 
  $age = $age ?? null; 
  if($name == null || $age === null) { 
    return 'Name or Age need to be set';  
   } else { 

    return '<div> 

         <li>Name: ' . $name . ' </li> 

         <li>Age: ' . $age . '</li> 

         <li>Country:  ' .  $country . ' </li> 

    </div>'; 
  } 
} 

```

# 关注点分离

在一个适当的 MVC 架构中，我们需要将视图与获取数据的模型分开，控制器将负责处理业务逻辑。

在我们的简单应用程序中，我们将跳过控制器层，因为我们只想在一个公共页面中显示用户配置文件。前面的函数也被称为 MVC 架构中的模板渲染部分。

虽然有一些可用于 PHP 的框架可以直接使用 MVC 架构，但现在我们可以坚持我们已经拥有的东西并使其工作。

PHP 框架可以从空合并运算符中受益很多。在我曾经使用的一些代码中，我们经常使用三元运算符，但仍然需要添加更多的检查来确保值不是虚假的。

此外，三元运算符可能会令人困惑，并需要一些时间来适应。另一种选择是使用`isSet`函数。然而，由于`isSet`函数的性质，一些虚假的值将被 PHP 解释为已设置。

# 创建视图

现在我们的模型已经完成，有一个模板渲染函数，我们只需要创建一个视图，通过它我们可以查看每个配置文件。

我们的视图将放在一个`foreach`块中，并且我们将使用我们编写的模板来渲染正确的值：

```php
//listprofiles.php 

<html> 
<!doctype html> 
<head> 
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css"> 
</head> 
<body> 

<?php 
foreach($results as $item) { 
  echo profile_template($item->name, $item->age, $item->country; 
} 
?> 
</body> 
</html> 

```

让我们把上面的代码放到`index.php`中。

虽然我们可以安装 Apache 服务器，配置它来运行 PHP，安装新的虚拟主机和其他必要的功能，并将我们的 PHP 代码放入 Apache 文件夹中，但这需要时间。因此，为了测试这一点，我们可以只运行 PHP 的服务器进行开发。

要运行内置的 PHP 服务器（在[`php.net/manual/en/features.commandline.webserver.php`](http://php.net/manual/en/features.commandline.webserver.php)上阅读更多信息），我们将使用我们正在运行的文件夹，在终端内：

```php
**php -S localhost:8000**

```

如果我们打开浏览器，我们应该还看不到任何东西，**没有找到结果**。这意味着我们需要填充我们的数据库。

如果您的数据库连接出现错误，请确保将我们提供的正确数据库凭据替换到我们所做的每个`mysql_connect`调用中。

1.  为了向我们的数据库提供数据，我们可以创建一个简单的 SQL 脚本，就像这样：

```php
INSERT INTO user_profiles ('Chin Wu', 30, 'Mongolia'); 
INSERT INTO user_profiles ('Erik Schmidt', 22, 'Germany'); 
INSERT INTO user_profiles ('Rashma Naru', 33, 'India'); 

```

1.  让我们把它保存在一个名为`insert_profiles.sql`的文件中。在与 SQL 文件相同的目录中，通过以下命令登录 MySQL 客户端：

```php
 **mysql -u root -p**

```

1.  然后输入使用<数据库名称>：

```php
 **mysql>  use <database>;**

```

1.  通过运行 source 命令导入脚本：

```php
 **mysql> source insert_profiles.sql**

```

现在我们的用户资料页面应该显示如下：

![创建视图](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_01_001.jpg)

# 创建个人资料输入表单

现在让我们为用户创建 HTML 表单来输入他们的个人资料。

如果我们没有一个简单的方法让用户输入他们的用户资料细节，我们的个人资料应用就没有用处。

我们将创建个人资料输入表单如下：

```php
//create_profile.php 

<html> 
<body> 
<form action="post_profile.php" method="POST"> 

  <label>Name</label><input name="name"> 
  <label>Age</label><input name="age"> 
  <label>Country</label><input name="country"> 

</form> 
</body> 
</html> 

```

在这个个人资料帖子中，我们需要创建一个 PHP 脚本来处理用户发布的任何内容。它将从输入值创建一个 SQL 语句，并输出它们是否被插入。

我们可以再次使用空合并运算符来验证用户是否输入了所有值，并且没有留下未定义或空的值：

```php
$name = $_POST['name'] ?? ""; 

$age = $_POST['country'] ?? ""; 

$country = $_POST['country'] ?? ""; 

```

这可以防止我们在向数据库插入数据时累积错误。

首先，让我们创建一个变量来保存每个输入的数组：

```php
$input_values =  [ 
 'name' => $name, 
 'age' => $age, 
 'country' => $country 
]; 

```

上面的代码是一种新的 PHP 5.4+写数组的方式。在 PHP 5.4+中，不再需要使用实际的`array()`；作者个人更喜欢新的语法。

我们应该在我们的`UserProfile`类中创建一个新的方法来接受这些值：

```php
Class UserProfile { 

 public function insert_profile($values)  { 

 $link =  mysqli_connect('127.0.0.1', 'username','password', 'databasename'); 

 $q = " INSERT INTO " . $this->table . " VALUES ( '".$values['name']."', '".$values['age'] . "' ,'".$values['country']. "')"; 
   return mysqli_query($q); 

 } 
} 

```

与我们的个人资料模板渲染函数一样，我们不需要在函数中创建一个参数来保存每个参数，我们可以简单地使用一个数组来保存我们的值。

这样，如果需要向我们的数据库插入一个新字段，我们只需在 SQL `insert`语句中添加另一个字段。

趁热打铁，让我们创建编辑个人资料部分。

目前，我们假设使用此编辑个人资料的人是网站的管理员。

我们需要创建一个页面，假设`$_GET['id']`已经设置，那么我们将从数据库中获取用户并在表单上显示。代码如下：

```php
<?php 
require('class/userprofile.php');//contains the class UserProfile into 

$id = $_GET['id'] ?? 'No ID'; 
//if id was a string, i.e. "No ID", this would go into the if block 
if(is_numeric($id)) { 
  $profile =  new UserProfile(); 
  //get data from our database 
  $results =   $user->fetch_id($id); 
  if($results && $results->num_rows > 0  ) { 
     while($obj = $results->fetch_object()) 
   { 
          $name = $obj->name; 
          $age = $obj->age; 
       $country = $obj->country; 
      } 
        //display form with a hidden field containing the value of the ID 
?> 

  <form action="post_update_profile.php" method="post"> 

  <label>Name</label><input name="name" value="<?=$name?>"> 
  <label>Age</label><input name="age" value="<?=$age?>"> 
  <label>Country</label><input name="country" value="<?=country?>"> 

</form> 

  <?php 

  } else { 
         exit('No such user'); 
  } 

} else { 
  echo $id; //this  should be No ID'; 
 exit; 
}   

```

请注意，我们在表单中使用了所谓的快捷`echo`语句。这使我们的代码更简单，更易读。由于我们使用的是 PHP 7，这个功能应该是开箱即用的。

一旦有人提交表单，它就会进入我们的`$_POST`变量，我们将在我们的`UserProfile`类中创建一个新的`Update`函数。

# 管理员系统

最后，让我们创建一个简单的*网格*，用于与我们的用户资料数据库一起使用的管理员仪表板门户。我们对此的要求很简单：我们只需设置一个基于表格的布局，以行显示每个用户资料。

从网格中，我们将添加链接以便能够编辑个人资料，或者删除它，如果我们想要的话。在我们的 HTML 视图中显示表格的代码如下：

```php
<table> 
 <tr> 
  <td>John Doe</td> 
  <td>21</td> 
  <td>USA</td> 
  <td><a href="edit_profile.php?id=1">Edit</a></td> 
  <td><a href="profileview.php?id=1">View</a> 
  <td><a href="delete_profile.php?id=1">Delete</a> 
 </tr> 
</table> 
This script to this is the following: 
//listprofiles.php 
$sql = "SELECT * FROM userprofiles LIMIT $start, $limit ";  
$rs_result = mysqli_query ($sql); //run the query 

while($row = mysqli_fetch_assoc($rs_result) { 
?> 
    <tr> 
           <td><?=$row['name'];?></td> 
           <td><?=$row['age'];?></td>  
        <td><?=$row['country'];?></td>       

         <td><a href="edit_profile.php?id=<?=$id?>">Edit</a></td> 
          <td><a href="profileview.php?id=<?=$id?>">View</a> 
          <td><a href="delete_profile.php?id=<?=$id?>">Delete</a> 
           </tr> 

<?php 
} 

```

有一件事我们还没有创建：`delete_profile.php`页面。查看和编辑页面已经讨论过了。

`delete_profile.php`页面将如下所示：

```php
<?php 

//delete_profile.php 
$connection = mysqli_connect('localhost','<username>','<password>', '<databasename>'); 

$id = $_GET['id'] ?? 'No ID'; 

if(is_numeric($id)) { 
mysqli_query( $connection, "DELETE FROM userprofiles WHERE id = '" .$id . "'"); 
} else { 
 echo $id; 
} 
i(!is_numeric($id)) {  
exit('Error: non numeric \$id');  
 } else { 
echo "Profile #" . $id . " has been deleted"; 

?> 

```

当然，由于我们的数据库中可能有很多用户资料，我们必须创建一个简单的分页。在任何分页系统中，你只需要找出总行数和每页要显示的行数。我们可以创建一个函数，它将能够返回一个包含页码和每页要查看的数量的 URL。

从我们的查询数据库中，我们首先创建一个新的函数，让我们只选择数据库中的总项目数：

```php
class UserProfile{ 
 // .... Etc ... 
function count_rows($table) { 
      $dbconn = new mysqli('localhost', 'root', 'somepass', 'databasename');  
  $query = $dbconn->query("select COUNT(*) as num from '". $table . "'"); 

   $total_pages = mysqli_fetch_array($query); 

   return $total_pages['num']; //fetching by array, so element 'num' = count 
} 

```

对于我们的分页，我们可以创建一个简单的`paginate`函数，它接受页面的`base_url`，每页的行数（也称为每页要显示的记录数），以及找到的记录的总数：

```php
require('definitions.php'); 
require('db.php'); //our database class 

Function paginate ($base_url, $rows_per_page, $total_rows) { 
  $pagination_links = array(); //instantiate an array to hold our html page links 

   //we can use null coalesce to check if the inputs are  null   
  ( $total_rows || $rows_per_page) ?? exit('Error: no rows per page and total rows);  
     //we exit with an error message if this function is called incorrectly  

    $pages =  $total_rows % $rows_per_page; 
    $i= 0; 
       $pagination_links[$i] =  "<a href="http://". $base_url  . "?pagenum=". $pagenum."&rpp=".$rows_per_page. ">"  . $pagenum . "</a>"; 
      } 
    return $pagination_links; 

} 

```

这个函数将帮助在表格中显示上面的页面链接：

```php
function display_pagination($links) {
      $display = '<div class="pagination">
                  <table><tr>';
      foreach ($links as $link) {
               echo "<td>" . $link . "</td>";
      }

       $display .= '</tr></table></div>';

       return $display;
    }
```

请注意，我们遵循的原则是函数内部应该很少有`echo`语句。这是因为我们希望确保这些函数的其他用户在调试页面上出现神秘输出时不会感到困惑。

通过要求程序员回显函数返回的内容，可以更容易地调试我们的程序。此外，我们遵循关注点分离，我们的代码不输出显示，它只是格式化显示。

因此，任何未来的程序员都可以更新函数的内部代码并返回其他内容。这也使我们的函数可重用；想象一下，将来有人使用我们的函数，这样，他们就不必再次检查我们的函数中是否有一些错放的`echo`语句。

### 提示

**关于替代短标签的说明**

如你所知，另一种`echo`的方法是使用`<?= `标签。你可以这样使用：`<?="helloworld"?>`。这些被称为短标签。在 PHP 7 中，替代 PHP 标签已被移除。RFC 声明`<%`、`<%=`、`%>`和`<script language=php>`已被弃用。RFC 在[`wiki.php.net/rfc/remove_alternative_php_tags`](https://wiki.php.net/rfc/remove_alternative_php_tags)中表示，RFC 并未移除短开标签（`<?`）或带有`echo`的短开标签（`<?= `）。

由于我们已经铺好了创建分页链接的基础，现在我们只需要调用我们的函数。以下脚本就是使用前面的函数创建分页页面所需的全部内容：

```php
$mysqli = mysqli_connect('localhost','<username>','<password>', '<dbname>'); 

   $limit = $_GET['rpp'] ?? 10;    //how many items to show per page default 10; 

   $pagenum = $_GET['pagenum'];  //what page we are on 

   if($pagenum) 
     $start = ($pagenum - 1) * $limit; //first item to display on this page 
   else 
     $start = 0;                       //if no page var is given, set start to 0 
/*Display records here*/ 
$sql = "SELECT * FROM userprofiles LIMIT $start, $limit ";  
$rs_result = mysqli_query ($sql); //run the query 

while($row = mysqli_fetch_assoc($rs_result) { 
?> 
    <tr> 
           <td><?php echo $row['name']; ?></td> 
           <td><?php echo $row['age']; ?></td>  
        <td><?php echo $row['country']; ?></td>            
           </tr> 

<?php 
} 

/* Let's show our page */ 
/* get number of records through  */ 
   $record_count = $db->count_rows('userprofiles');  

$pagination_links =  paginate('listprofiles.php' , $limit, $rec_count); 
 echo display_pagination($paginaiton_links); 

```

我们页面链接的 HTML 输出在`listprofiles.php`中会看起来像这样：

```php
<div class="pagination"><table> 
 <tr> 
        <td> <a href="listprofiles.php?pagenum=1&rpp=10">1</a> </td> 
         <td><a href="listprofiles.php?pagenum=2&rpp=10">2</a>  </td> 
        <td><a href="listprofiles.php?pagenum=3&rpp=10">2</a>  </td> 
    </tr> 
</table></div> 

```

# 总结

正如你所看到的，我们对 null 合并有很多用例。

我们学习了如何创建一个简单的用户配置文件系统，以及如何在从数据库获取数据时使用 PHP 7 的 null 合并功能，如果没有记录，则返回 null。我们还了解到，null 合并运算符类似于三元运算符，只是如果没有数据，默认返回 null。

在下一章中，我们将有更多用例来使用其他 PHP 7 功能，特别是在为我们的项目创建数据库抽象层时。


# 第二章：构建一个数据库类和简单的购物车

对于我们以前的应用程序，只是用户配置文件，我们只创建了一个简单的**创建-读取-更新-删除（CRUD）**数据库抽象层 - 基本的东西。在本章中，我们将创建一个更好的数据库抽象层，它将允许我们做的不仅仅是基本的数据库功能。

除了简单的 CRUD 功能之外，我们将在数据库抽象类中添加结果操作。我们将在我们的数据库抽象类中构建以下功能：

+   将整数转换为其他更准确的数字类型

+   数组转对象

+   `firstOf()`方法：允许我们选择数据库查询结果的第一个结果

+   `lastOf()`方法：允许我们选择数据库查询结果的最后一个结果

+   `iterate()`方法：允许我们迭代结果并以我们将发送到此函数的格式返回它

+   `searchString()`方法：在结果列表中查找字符串

我们可能会根据需要添加更多的功能。在本章的末尾，我们将应用数据库抽象层来构建一个简单的**购物车**系统。

购物车很简单：已经登录的用户应该能够点击一些出售的物品，点击**添加到购物车**，并获取用户的详细信息。用户验证了他们的物品后，然后点击购买按钮，我们将把他们的购物车物品转移到购买订单中，他们将填写交货地址，然后保存到数据库中。

# 构建数据库抽象类

在 PHP 中，创建一个类时，有一种方法可以在每次初始化该类时调用某个方法。这称为类的构造函数。大多数类都有构造函数，所以我们将有自己的构造函数。构造函数的函数名是用两个下划线和`construct()`关键字命名的，就像这样：`function __construct()`。两个下划线的函数也被称为魔术方法。

在我们的数据库抽象类中，我们需要创建一个构造函数，以便能够返回`mysqli`生成的`link`对象：

```php
 Class DB { 

  public $db; 

  //constructor 
  function __construct($server, $dbname,$user,$pass) { 
    //returns mysqli $link $link = mysqli_connect(''); 
    return $this->db = mysqli_connect($server, $dbname, $user, $pass); 
  } 
} 

```

## 原始查询方法

`query`方法将执行传递给它的任何查询。我们将在`query`方法中调用 MySQLi 的`db->query`方法。

它是什么样子的：

```php
public function query($sql) { 
 $results =   $this->db->query($sql); 
 return $results; 
} 

```

## 创建方法

对于我们的数据库层，让我们创建`create`方法。通过这个方法，我们将使用 SQL 语法将项目插入到数据库中。在 MySQL 中，语法如下：

```php
INSERT INTO [TABLE] VALUES ([val1], [val2], [val3]); 

```

我们需要一种方法将数组值转换为以逗号分隔的字符串：

```php
 function create ($table, $arrayValues) { 
  $query = "INSERT INTO  `" . $table . " ($arrayVal);  //TODO: setup arrayVal 
  $results = $this->db->query($link, $query); 
} 

```

## 读取方法

对于我们的`db`层，让我们创建`read`方法。通过这个方法，我们将只使用 SQL 语法查询我们的数据库。

MySQL 中的语法如下：

```php
SELECT * FROM [table] WHERE [key] = [value] 

```

我们需要创建一个能够接受括号中的前置参数的函数：

```php
public function read($table, $key, $value){ 
         $query  = SELECT * FROM $table WHERE `". $key . "` =  " . $value; 
     return $this->db->query($query); 
} 

```

## 选择所有方法

我们的`read`方法接受一个`key`和`value`对。然而，可能有些情况下我们只需要选择表中的所有内容。在这种情况下，我们应该创建一个简单的方法来选择表中的所有行，它只接受要选择的`table`作为参数。

在 MySQL 中，您只需使用以下命令选择所有行：

```php
SELECT * FROM [table]; 

```

我们需要创建一个能够接受括号中的前置参数的函数：

```php
public function select_all($table){ 
         $query  = "SELECT * FROM " . $table; 
     return $this ->query($query); 
} 

```

## 删除方法

对于我们的`db`层，让我们创建`delete`方法。通过这个方法，我们将使用 SQL 语法删除数据库中的一些项目。

MySQL 语法很简单：

```php
DELETE FROM [table] WHERE [key] = [val]; 

```

我们还需要创建一个能够接受括号中的前置参数的函数：

```php
public function delete($table, $key, $value){ 
         $query  = DELETE FROM $table WHERE `". $key . "` =  " . $value; 
     return $this->query($query); 
} 

```

## 更新方法

对于我们的数据库层，让我们创建一个`update`方法。通过这个方法，我们将能够使用 SQL 语法更新数据库中的项目。

MySQL 语法如下：

```php
UPDATE [table] SET [key1] = [val1], [key2] => [val2]  WHERE [key] = [value] 

```

### 注意

请注意，`WHERE`子句可以比一个键值对更长，这意味着您可以向语句添加`AND`和`OR`。这意味着，除了使第一个键动态化之外，`WHERE`子句需要能够接受`AND`/`OR`作为其参数。

例如，您可以为`$where`参数编写以下内容，以选择`firstname`为`John`且`lastname`为`Doe`的人：

```php
firstname='John' AND lastname='Doe' 

```

这就是为什么我们在函数中将条件作为一个字符串参数的原因。我们数据库类中的`update`方法最终将如下所示：

```php
public function update($table, $updateSetArray, $where){ 
     Foreach($updateSetArray as $key => $value) { 
         $update_fields .= $key . "=" . $value . ","; 
     } 
      //remove last comma from the foreach loop above 
     $update_fields = substr($update_fields,0, str_len($update_fields)-1); 
    $query  = "UPDATE " . $table. " SET " . $updateFields . " WHERE " $where; //the where 
    return $this->query($query); 
} 

```

## first_of 方法

在我们的数据库中，我们将创建一个`first_of`方法，它将过滤掉其余的结果，只获取第一个结果。我们将使用 PHP 的`reset`函数，它只获取数组中的第一个元素：

```php
//inside DB class  
public function first_of($results) { 
  return reset($results); 
} 

```

## last_of 方法

`last_of`方法类似；我们可以使用 PHP 的`end`函数：

```php
//inside DB class  
public function last_of($results) { 
  Return end($results); 
} 

```

## iterate_over 方法

`iterate_over`方法将是一个简单添加格式的函数 - 在 HTML 代码之前和之后 - 例如，对于我们从数据库中获得的每个结果：

```php
public function iterate_over($prefix, $postfix, $items) { 
    $ret_val = ''; 
    foreach($items as $item) { 
        $ret_val .= $prefix. $item . $postfix; 
    } 
    return $ret_val; 
} 

```

## searchString 方法

给定一组结果，我们将查找某个字段中的内容。这样做的方法是生成类似于以下的 SQL 代码：

```php
    SELECT * FROM {table} WHERE {field} LIKE '%{searchString}%';
```

该函数将接受表和字段，以检查表中的搜索字符串`needle`：

```php
public function search_string($table, $column, $needle) { 
 $results = $this->query("SELECT * FROM `".$table."` WHERE " .    $column . " LIKE '%" . $needle. "%'"); 
   return $results; 
} 

```

## 使用 convert_to_json 方法实现一个简单的 API

有时我们希望数据库的结果以特定格式呈现。一个例子是当我们将结果作为 JSON 对象而不是数组处理时。这在您构建一个简单的 API 以供移动应用程序使用时非常有用。

这可能是可能的，例如，在另一个需要以特定格式（例如 JSON 格式）的系统中，我们可以将对象转换为 JSON 并发送它。

在 PHP 中，有一个`json_encode`方法，它将任何数组或对象转换为 JSON 表示。我们类的方法将只是将传递给它的值返回为`json`：

```php
function convertToJSON($object) { 
   return json_encode($object); 
   } 

```

# 购物车

现在我们将构建一个简化的购物车模块，它将利用我们新建的数据库抽象类。

让我们来规划一下购物车的功能：

+   **购物清单页面**：

+   购物者应该看到几个带有名称和价格的物品

+   购物者应该能够点击每个物品旁边的复选框，将其添加到购物车中

+   **结账页面**：

+   物品清单及其价格

+   总计

+   **确认页面**：

+   输入详细信息，如账单地址、账单信用卡号，当然还有名字

+   购物者还应该能够指定将商品发送到哪个地址

## 构建购物清单

在这个页面中，我们将创建基本的 HTML 块，以显示购物者可能想要购买的物品清单。

我们将使用与之前相同的模板系统，但是不再将整个代码放在一个页面中，而是将页眉和页脚分开，并简单地在我们的文件中包含它们使用`include()`。我们还将使用相同的 Bootstrap 框架来使我们的前端看起来漂亮。

### 物品模板渲染函数

我们将创建一个物品渲染函数，它将在`div`中渲染所有我们的购物物品。该函数将简单地返回一个带有物品价格、名称和图片的 HTML 标记：

```php
//accepts the database results as an array and calls db functions render_shopping_items($items) 
{ 
$db->iterate_over("<td>", "</td>", $item_name); 
    foreach($items as $item) { 
     $item->name.  ' ' .$item->price . ' ' . $item->pic; 

   } 
$resultTable .= "</table>"; 
} 

```

在上面的代码中，我们使用了我们新创建的`iterate_over`函数，该函数格式化数据库的每个值。最终结果是我们有了一个我们想要购买的物品的表格。

让我们创建一个简单的布局结构，每个页面都会得到页眉和页脚，并且从现在开始，只需包含它们：

在`header.php`中：

```php
<html> 
<!doctype html> 
<head> 
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css"> 
</head> 
<body> 

```

在`footer.php`中：

```php
<div class="footer">Copyright 2016</div></body> 
</html> 

```

在`index.php`中：

```php
<?php 
require('header.php'); 
//render item_list code goes here 
require('itemslist.php'); //to be coded  
require('footer.php'); 
?> 

```

现在让我们创建`itemslist.php`页面，该页面将包含在`index.php`中：

```php
<?php  
include('DB.php'); 
$db = new DB(); 
$table = 'shopping_items'; 
$results = $db->select_all($table); 
//calling the render function created earlier: 
foreach(as $item) { 
  echo render_shopping_items($results);  
} 

?> 
//shopping items list goes here. 

```

我们的函数已经准备好了，但是我们的数据库还不存在。我们还需要填充我们的数据库。

通过在我们的 MySQL 数据库中创建`shopping_items`表来创建一些购物物品：

```php
CREATE TABLE shopping_items ( 
    id INT(11) NOT NULL AUTO_INCREMENT, 
    name VARCHAR(255) NOT NULL, 
    price DECIMAL(6,2) NOT NULL, 
   image VARCHAR(255) NOT NULL, 
PRIMARY KEY  (id)  
); 

```

让我们运行 MySQL，并将以下物品插入到我们的数据库中：

```php
INSERT INTO `shopping_items` VALUES (NULL,'Tablet', '199.99', 'tablet.png'); 
INSERT INTO `shopping_items` VALUES (NULL, 'Cellphone', '199.99', 'cellphone.png'); 
INSERT INTO `shopping_items` (NULL,'Laptop', '599.99', 'Laptop.png'); 
INSERT INTO `shopping_items` (NULL,'Cable', '14.99', 'Cable.png'); 
INSERT INTO `shopping_items` (NULL, 'Watch', '100.99', 'Watch.png'); 

```

将其保存在一个名为`insert_shopping_items.sql`的文件中。然后，在与`insert_shopping_items.sql`文件相同的目录中：

1.  登录到 MySQL 客户端并按照以下步骤进行：

```php
**mysql -u root -p**

```

1.  然后键入`use <数据库名称>`：

```php
**mysql>  use <database>;**

```

1.  使用`source`命令导入脚本：

```php
**mysql> source insert_shopping_items.sql**

```

当我们运行`SELECT * FROM shopping_items`时，我们应该看到以下内容：

![项目模板渲染函数](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/B05285_02_01.jpg)

## 向购物清单页面添加复选框

现在让我们为用户创建 HTML 复选框，以便能够选择购物物品。我们将创建以下形式来插入数据：

```php
//items.php 

<html> 
<body> 

<form action="post_profile.php" method="POST"> 
<table> 
  <input type="checkbox" value="<item_id>"> <td><item_image></td> 
  <td><item_name></td><td> 
 </table> 
</form> 
</body> 
</html> 

```

为此，我们需要修改我们的`render_items`方法以添加复选框：

```php
public function render_items($itemsArray)  { 

foreach($itemsArray as $item) { 
  return '<tr> 
           <td><input type="checkbox" name="item[]" value="' . $item->id. '">' .  . '</td><td>' . $item->image .'</td> 
<td>'. $item->name . '</td> 
'<td>'.$item->price . '</td> 
'</tr>'; 
} 
} 

```

在下一页上，当用户单击**提交**时，我们将需要获取所有 ID 并存储到一个数组中。

由于我们将复选框命名为`item[]`，我们应该能够通过`$_POST['item']`作为数组获取值。基本上，所有被选中的物品将作为数组存储在 PHP 的`$_POST`变量中，这将允许我们获取所有值以保存数据到我们的数据库中。让我们循环遍历结果的 ID，并在我们的数据库中获取每个物品的价格并将每个物品保存在名为`itemsArray`的数组中，其中键是物品的名称，值是物品的价格。

```php
$db = new DB(); 
$itemsArray= []; //to contain our items - since PHP 5.4, an array can be defined with []; 
foreach($_POST['item'] as $itemId) { 

   $item = $db->read('shopping_items', 'id', $itemId); 
   //this produces the equivalent SQL code: SELECT * FROM shopping_items WHERE id = '$itemId'; 
   $itemsArray[$item->name] = $item-price;  

} 

```

我们将首先与用户确认购买的物品。现在我们只会将物品和总金额保存到 cookie 中。我们将在结账页面上访问 cookie 的值，该页面将接受用户的详细信息，并在提交结账页面时将其保存到我们的数据库中。

### 提示

PHP 会话与 cookie：对于不太敏感的数据，例如用户购买的物品清单，我们可以使用 cookie，它实际上将数据（以纯文本形式！）存储在浏览器中。如果您正在构建此应用程序并在生产中使用它，建议使用会话。要了解有关会话的更多信息，请访问[`php.net/manual/en/features.sessions.php`](http://php.net/manual/en/features.sessions.php)。

## PHP 中的 Cookies

在 PHP 中，要启动一个 cookie，只需调用`setcookie`函数。为了将我们购买的物品保存到 cookie 中，我们必须对数组进行序列化，原因是 cookie 只能将值存储为字符串。

在这里，我们将物品保存到 cookie 中：

```php
setcookie('purchased_items', serialize($itemsArray), time() + 900); 

```

前面的 cookie 将在`purchased_items` cookie 中将物品存储为数组。它将在 15 分钟后过期（900 秒）。但是，请注意`time()`函数的调用，它返回当前时间的 Unix 时间戳。在 PHP 中，当达到最后一个参数中设置的时间时，cookie 将会过期。

### 注意

调试基于 cookie 的应用程序有时会令人沮丧。确保`time()`生成的时间戳确实显示当前时间。

例如，可能您最近重新格式化了您的计算机，由于某种原因无法正确设置时间。要测试`time()`，只需运行一个带有`time()`调用的 PHP 脚本，并检查[`www.unixtimestamp.com/`](http://www.unixtimestamp.com/)是否几乎相同。

## 构建结账页面

最后，我们将创建一个表单，用户可以在结账后输入他们的详细信息。

首先，我们需要为客户建立数据库表。让我们称这个表为`purchases`。我们需要存储客户的姓名、地址、电子邮件、信用卡、购买的物品和总额。我们还应该存储购买交易的时间，并使用唯一的主键来索引每一行。

以下是要导入到我们的 MySQL 数据库中的表的架构：

```php
CREATE TABLE purchases ( 
    id INT(11) NOT NULL AUTO_INCREMENT, 
    customer_name VARCHAR(255) NOT NULL, 
    address DECIMAL(6,2) NOT NULL, 
    email DECIMAL(6,2) NOT NULL, 
    credit_card VARCHAR(255) NOT NULL, 
    items TEXT NOT NULL, 
    total DECIMAL(6,2) NOT NULL, 
    created DATETIME NOT NULL, 
    PRIMARY KEY (id) 
); 

```

导入的一种方法是创建一个名为`purchases.sql`的文件，然后登录到您的 MySQL 命令行工具。

然后，您可以选择要使用的数据库：

```php
**USE <databasename>**

```

最后，假设您在与`purchases.sql`相同的目录中，您可以运行：

```php
**SOURCE purchases.sql** 

```

最后，通过创建一个简单的表单，包括地址、信用卡和买家姓名等详细信息的输入字段来完成：

```php
<form action="save_checkout.php" method="post"> 
<table> 
  <tr> 
   <td>Name</td><td><input type="text" name="fullname"></td>  
  </tr>  

 <tr> 
<td>Address</td><td><input type="text" name="address"></td> 
</tr> 
<tr> 
<td>Email</td><td><input type="text" name="email"></td> 
</tr> 

<tr>  
  <td>Credit Card</td><td><input type="text" name="credit_card"></td> 
 </tr> 
<tr>  
  <td colspan="2"><input type="submit" name="submit" value="Purchase"></td> 
 </tr> 

</table> 
</form> 

```

这是它的样子：

![构建结账页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/B05285_02_02.jpg)

最后，我们将像往常一样将所有内容保存到我们的数据库中的另一个表中，使用我们的`DB`类。为了计算总金额，我们将查询数据库的价格，并使用 PHP 的`array_sum`来获得总金额：

```php
$db = new DB($server,$dbname,$name,$password); 

//let's get the other details of the customer 
$customer_name = $_POST['fullname']; 
$address = $_POST['address']; 
$email = $_POST['email']; 
$credit_card = $_POST['credit_card]; 
$time_now = date('Y-m-d H:i:s'); 

foreach($purchased_items as $item) { 
  $prices[] = $item->price; 
} 

//get total using array_sum 
$total = array_sum($prices); 

$db->insert('purchases', [ 
   'address' => $address, 
'email' => $email, 
'credit_card' => $credit_card, 
 **'items' => //<all the items and prices>//,** 
   'total' => $total, 
    'purchase_date' => $timenow 
  ]);  
?> 

```

为了保持简单，正如您在突出显示的代码中所看到的，我们需要将所有购买的物品收集到一个长字符串中，以保存在我们的数据库中。以下是如何连接每个物品和它们的价格：

```php
foreach($purchased_items as $item) { 
   $items_text .= $item->name ":" . $item->price .  "," 
} 

```

然后我们可以将这些数据保存到变量`$items_text`中。我们将更新前面突出显示的代码，并将文本`<所有物品和价格>`更改为`$items_text`：

```php
... 
  'items' => $items_text 
 ... 

```

在我们的代码中，`foreach`循环应该放在调用`$db->insert`方法之前。

## 感谢页面

最后，我们已经将数据保存到我们的`purchased_items`表中。现在是时候向我们的客户说声谢谢并发送一封电子邮件了。在我们的`thankyou.php`的 HTML 代码中，我们将只写一张感谢便条，并让用户知道他们的购买情况即将收到一封电子邮件。

这是一个屏幕截图：

![感谢页面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/B05285_02_03.jpg)

我们将文件命名为`thankyou.php`，它的 HTML 代码非常简单：

```php
<!DOCTYPE html> 
<html> 
<head> 
   <!-- Latest compiled and minified CSS --> 
   <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous"> 
   <title>Thank you for shopping at example.info</title> 
</head> 
<body> 
 <div class="container"> 
        <div class="row"> 
            <div class="col-lg-12 text-center"> 
                <h1>Thank you for shopping at example.info</h1> 
                     <p>Yey! We're really happy for choosing us to shop online. We've sent you an email of your purchases. </p> 
                     <p>Let us know right away if you need anything</p> 
            </div> 
        </div> 
    </div> 
</body> 
</html> 

```

使用 PHP 发送电子邮件是使用`mail()`函数完成的：

```php
mail("<to address>", "Your purchase at example.com","Thank you for purchasing...", "From: <from address>"); 

```

第三个参数是我们电子邮件的消息。在代码中，我们仍然需要添加购买的细节。我们将循环遍历我们之前制作的 cookie 和价格，然后输出总金额，并发送消息：

```php
$mail_message = 'Thank you for purchasing the following items'; 
$prices = []; 
$purchased_items = unserialize($_COOKIE['purchased_items']); 
foreach($purchased_items as $itemName => $itemPrice) { 
  $mail_message .=  $itemName . ": " .$itemPrice . "\r\n \r\n"; 
  //since this is a plain text email, we will use \r\n - which are escape strings for us to add a new line after each price. 
  $prices[] = $itemPrice; 
} 

$mail_message .= "The billing total of your purchases is " . array_sum($prices); 

mail($_POST['email'], "Thank you for shopping at example.info here is your bill", $mail_message, "From: billing@example.info"); 

```

我们可以将前面的代码添加到我们的`thankyou.php`文件的最后。

# 安装 TCPDF

您可以从 sourceforge 下载 TCPDF 库，[`sourceforge.net/projects/tcpdf/`](https://sourceforge.net/projects/tcpdf/)

TCPDF 是用于编写 PDF 文档的 PHP 类。

一个带有 TCPDF 示例的 PHP 示例代码如下：

```php
//Taken from http://www.tcpdf.org/examples/example_001.phps 

// Include the main TCPDF library (search for installation path). 
require_once('tcpdf_include.php'); 

// create new PDF document 
$pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false); 

// set document information 
$pdf->SetCreator(PDF_CREATOR); 
$pdf->SetAuthor('Nicola Asuni'); 
$pdf->SetTitle('TCPDF Example 001'); 
$pdf->SetSubject('TCPDF Tutorial'); 
$pdf->SetKeywords('TCPDF, PDF, example, test, guide'); 

// set default header data 
$pdf->SetHeaderData(PDF_HEADER_LOGO, PDF_HEADER_LOGO_WIDTH, PDF_HEADER_TITLE.' 001', PDF_HEADER_STRING, array(0,64,255), array(0,64,128)); 
$pdf->setFooterData(array(0,64,0), array(0,64,128)); 

// set header and footer fonts 
$pdf->setHeaderFont(Array(PDF_FONT_NAME_MAIN, '', PDF_FONT_SIZE_MAIN)); 
$pdf->setFooterFont(Array(PDF_FONT_NAME_DATA, '', PDF_FONT_SIZE_DATA)); 

// set default monospaced font 
$pdf->SetDefaultMonospacedFont(PDF_FONT_MONOSPACED); 

// set margins 
$pdf->SetMargins(PDF_MARGIN_LEFT, PDF_MARGIN_TOP, PDF_MARGIN_RIGHT); 
$pdf->SetHeaderMargin(PDF_MARGIN_HEADER); 
$pdf->SetFooterMargin(PDF_MARGIN_FOOTER); 

// set auto page breaks 
$pdf->SetAutoPageBreak(TRUE, PDF_MARGIN_BOTTOM); 

// set image scale factor 
$pdf->setImageScale(PDF_IMAGE_SCALE_RATIO); 

// set some language-dependent strings (optional) 
if (@file_exists(dirname(__FILE__).'/lang/eng.php')) { 
    require_once(dirname(__FILE__).'/lang/eng.php'); 
    $pdf->setLanguageArray($l); 
} 

// --------------------------------------------------------- 

// set default font subsetting mode 
$pdf->setFontSubsetting(true); 

// Set font 
// dejavusans is a UTF-8 Unicode font, if you only need to 
// print standard ASCII chars, you can use core fonts like 
// helvetica or times to reduce file size. 
$pdf->SetFont('dejavusans', '', 14, '', true); 

// Add a page 
// This method has several options, check the source code documentation for more information. 
$pdf->AddPage(); 

// set text shadow effect 
$pdf->setTextShadow(array('enabled'=>true, 'depth_w'=>0.2, 'depth_h'=>0.2, 'color'=>array(196,196,196), 'opacity'=>1, 'blend_mode'=>'Normal')); 

// Set some content to print 
$html = <<<EOD 
<h1>Welcome to <a href="http://www.tcpdf.org" style="text-decoration:none;background-color:#CC0000;color:black;">&nbsp;<span style="color:black;">TC</span><span style="color:white;">PDF</span>&nbsp;</a>!</h1> 
<i>This is the first example of TCPDF library.</i> 
<p>This text is printed using the <i>writeHTMLCell()</i> method but you can also use: <i>Multicell(), writeHTML(), Write(), Cell() and Text()</i>.</p> 
<p>Please check the source code documentation and other examples for further information.</p> 
<p style="color:#CC0000;">TO IMPROVE AND EXPAND TCPDF I NEED YOUR SUPPORT, PLEASE <a href="http://sourceforge.net/donate/index.php?group_id=128076">MAKE A DONATION!</a></p> 
EOD; 

// Print text using writeHTMLCell() 
$pdf->writeHTMLCell(0, 0, '', '', $html, 0, 1, 0, true, '', true); 

// --------------------------------------------------------- 

// Close and output PDF document 
// This method has several options, check the source code documentation for more information. 
$pdf->Output('example_001.pdf', 'I'); 

```

有了这个例子，我们现在可以使用前面的代码并稍微修改一下，以便创建我们自己的发票。我们只需要相同的 HTML 样式和我们总计生成的值。让我们使用相同的代码并更新值到我们需要的值。

在这种情况下，我们将设置作者为网站的名称`example.info`。并将我们的主题设置为`发票`。

首先，我们需要获取主要的 TCPDF 库。如果您将其安装在不同的文件夹中，我们可能需要提供一个相对路径，指向`tcpdf_include.php`文件：

```php
require_once('tcpdf_include.php'); 

```

这将使用类的默认方向和默认页面格式实例化一个新的 TCPDF 对象：

```php
$pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false); 

$pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false); 

// set document information 
$pdf->SetCreator(PDF_CREATOR); 
$pdf->SetAuthor('Example.Info'); 
$pdf->SetTitle('Invoice Purchases'); 
$pdf->SetSubject('Invoice'); 
$pdf->SetKeywords('Purchases, Invoice, Shopping'); 
s 

$html = <<<EOD 
<h1>Example.info Invoice </h1> 
<i>Invoice #0001.</i> 
EOD; 

```

现在，让我们使用 HTML 来创建一个客户购买的 HTML 表格：

```php
$html .= <<<EOD 
<table> 
  <tr> 
    <td>Item Purchases</td> 
    <td>Price</td> 
  </tr> 
EOD; 

```

### 注意

这种多行字符串的写法被称为 heredoc 语法。

让我们通过实例化我们的`DB`类来创建与数据库的连接：

```php
$db = new DBClass('localhost','root','password', 'databasename'); 
We shall now query our database with our database class: 

$table = 'purchases'; 
$column = 'id';  
$findVal = $_GET['purchase_id']; 

   $result = $db->read ($table, $column, $findVal); 

foreach($item = $result->fetch_assoc()) { 
$html .=   "<tr> 
         <td>". $item['customer_name']. "</td> 
         <td>" . $item['items'] . " 
</tr>"; 

$total = $items['total']; //let's save the total in a variable for printing in a new row 

} 

$html .= '<tr><td colspan="2" align="right">TOTAL: ' ".$total. " ' </td></tr>'; 

$html .= <<<EOD 
</table> 
EOD; 

$pdf->writeHTML($html, true, false, true, false, ''); 

$pdf->Output('customer_invoice.pdf', 'I'); 

```

在创建 PDF 时，重要的是要注意，大多数 HTML 到 PDF 转换器都是简单创建的，并且可以解释简单的内联 CSS 布局。我们使用表格打印出每个项目，这对于表格数据来说是可以的。它为布局提供了结构，并确保事物被正确对齐。

# 管理购买的管理员

我们将建立管理系统来处理所有的购买。这是为了跟踪每个从我们网站购买东西的客户。它将包括两个页面：

+   所有购买了东西的客户的概述

+   能够查看客户购买的物品

我们还将在这些页面上添加一些功能，以便管理员更容易地更改客户的信息。

我们还将创建一个简单的**htaccess apache 规则**，以阻止其他人访问我们的管理站点，因为它包含非常敏感的数据。

让我们首先开始选择我们`purchases`表中的所有数据：

```php
<?php 
//create an html variable for printing the html of our page: 
$html = '<!DOCTYPE html><html><body>'; 

$table = 'purchases'; 
$results = $db->select_all($table); 

//start a new table structure and set the headings of our table: 
$html .= '<table><tr> 
    <th>Customer name</th> 
    <th>Email</th> 
    <th>Address</th> 
    <th>Total Purchase</th> 
</tr>'; 

//loop through the results of our query: 
while($row = $results->fetch_assoc()){ 
    $html .= '<tr><td>'$row['customer_name'] . '</td>'; 
    $html .= '<td>'$row['email'] . '</td>'; 
    $html .= '<td>'$row['address'] . '</td>'; 
    $html .= '<td>'$row['purchase_date'] . '</td>'; 
    $html .= '</tr>'; 
} 

$html .= '</table>'; 
$html .= '</body></html>; 

//print out the html 
echo $html; 

```

现在，我们将添加一个链接到我们客户数据的另一个视图。这个视图将使管理员能够查看他们所有的购买。我们可以通过在客户姓名上添加一个链接，将第一个页面链接到客户购买的详细视图，方法是将我们添加客户姓名到`$html`变量的行更改为：

```php
    $html .= '<tr><td><a href="view_purchases.php?pid='.$row['id'] .'">'$row['customer_name'] . '</a></td>'; 

```

请注意，我们已经将`$row['id']`作为 URL 的一部分。现在我们可以通过`$_GET['pid']`值访问我们将要获取的数据的 ID 号。

让我们在一个新文件`view_purchases.php`中创建查看客户购买物品的代码：

```php
<?php 
//create an html variable for printing the html of our page: 
$html = '<!DOCTYPE html><html><body>'; 

$table = 'purchases; 
$column = 'id'; 
**$purchase_id = $_GET['pid'];** 
$results = $db->read($table, $column, $purchase_id);  
//outputs: 
// SELECT * FROM purchases WHERE id = '$purchase_id'; 

//start a new table structure and set the headings of our table: 
$html .= '<table><tr><th>Customer name</thth>Total Purchased</th></tr>'; 
//loop through the results of our query: 
while($row = $results->fetch_assoc()){ 
    $html .= '<tr><td>'$row['customer_name'] . '</td>'; 
    $html .= '<tr><td>'$row['email'] . '</td>'; 
    $html .= '<tr><td>'$row['address'] . '</td>'; 
    $html .= '<tr><td>'$row['purchase_date'] . '</td>'; 
    $html .= '</tr>'; 
} 
$html .= '</table>'; 
echo $html; 

```

在上面的代码中，我们使用了`$_GET['id']`变量来查找客户的确切购买记录。虽然我们可以只使用客户姓名来查找表`purchases`中客户的购买记录，但这将假定客户只通过我们的系统购买了一次。此外，我们没有使用客户姓名来确定我们是否有时有相同姓名的客户。

通过使用表`purchases`的主要 ID，在我们的情况下，通过选择`id`字段来确保我们选择了特定的唯一购买。请注意，由于我们的数据库很简单，我们可以只查询数据库中的一个表 - 在我们的情况下是`purchases`表。

也许一个更好的实现方法是将“购买”表分成两个表 - 一个包含客户的详细信息，另一个包含已购买物品的详细信息。这样，如果同一个客户返回，他们的详细信息可以在下次自动填写，我们只需要将新购买的物品链接到他们的账户上。

在这种情况下，“购买”表将简单地称为“已购买物品”表，每个物品将与客户 ID 相关联。客户的详细信息将存储在一个包含其唯一地址、电子邮件和信用卡详细信息的“客户”表中。

然后，您将能够向客户展示他们的购买历史。每次客户从商店购买物品时，交易日期将被记录下来，您需要按照每笔交易的日期和时间对历史记录进行排序。

# 总结

太好了，我们完成了！

我们刚刚学会了如何构建一个简单的数据库抽象层，以及如何将其用于购物车。我们还学习了关于 cookies 和使用 TCPDF 库构建发票。

在下一章中，我们将构建一个完全不同的东西，并使用会话来保存用户的当前信息，以构建基于 PHP 的聊天系统。


# 第三章：构建社交通讯服务

根据可靠的词典，通讯是定期发布给社会、企业或组织成员的公告。

在本章中，我们将构建一个电子邮件通讯，允许会员订阅和取消订阅，接收特定类别的更新，并允许营销人员检查有多少人访问了某个链接。

我们将为用户构建一个身份验证系统，以便登录和退出通讯管理系统，这是一个社交登录系统，供订阅会员轻松检查其订阅以及为订阅者和管理员提供简单的仪表板。

# 身份验证系统

在本章中，我们将实现一个新的身份验证系统，以允许通讯通讯的管理员进行身份验证。自 PHP5 以来，PHP 已经改进并添加了一个功能，面向对象的开发人员已经用来分隔命名空间。

让我们首先定义一个名为`Newsletter`的命名空间，如下所示：

```php
<?php 
namespace Newsletter;  
//this must always be in every class that will use namespaces 
class Authentication { 
} 
?> 

```

在上面的示例中，我们的`Newsletter`命名空间将有一个`Authentication`类。当其他类或 PHP 脚本需要使用`Newsletter`的`Authentication`类时，他们可以简单地使用以下代码声明它：

```php
Use Newsletter\Authentication; 

```

在我们的`Newsletter`类中，让我们使用**bcrypt**创建一个简单的用户检查，这是一种流行且安全的创建和存储散列密码的方法。

### 注意

自 PHP 5.5 以来，bcrypt 已内置到`password_hash()` PHP 函数中。PHP 的`password_hash()`函数允许密码成为散列。相反，当您需要验证散列是否与原始密码匹配时，可以使用`password_verify()`函数。

我们的类将非常简单-它将有一个用于验证输入的电子邮件地址和散列密码是否与数据库中的相同的函数。我们必须创建一个只有一个方法`verify()`的简单类，该方法接受用户的电子邮件和密码。我们将使用`bcrypt`来验证散列密码是否与我们数据库中的相同：

```php
Class Authorization { 
     public function verify($email, $password) { 
         //check for the $email and password encrypted with bcrypt 
         $bcrypt_options = [ 
            'cost' => 12, 
            'salt' => 'secret' 
         ]; 
         $password_hash = password_hash($password, PASSWORD_BCRYPT, $bcrypt_options); 
         $q= "SELECT * FROM users WHERE email = '". $email. "' AND password = '".$password_hash. "'"; 
         if($result = $this->db->query($q)) { 
                     while ($obj = results->fetch_object()) { 
                           $user_id = $obj->id; 
} 

         } else { 
   $user_id = null; 
} 
         $result->close(); 
         $this->db->close(); 
         return $user_id; 

    } 
} 

```

然而，我们需要让`DB`类能够在我们的数据库中执行简单的查询。对于这个简单的一次性项目，我们可以在我们的`Authentication`类中简单使用依赖注入的概念。

我们应该创建一个相当简单的 IOC 容器类，它允许我们实例化数据库。

让我们称之为`DbContainer`，它允许我们将类（例如`Authentication`）连接到`DB`类：

```php
Namespace Newsletter; 
use DB; 
Class DbContainer { 
   Public function getDBConnection($dbConnDetails) {  
   //connect to database here: 
    $DB = new \DB($server, $username, $password, $dbname); 
       return $DB; 
  } 
} 

```

但是，如果您立即使用此函数，将会出现一个错误，指出找不到文件并将加载`DB`类。

以前，我们使用了`use`系统来要求类。为了使其工作，我们需要创建一个自动加载程序函数来加载我们的`DB`类，而无需使用`require`语句。

在 PHP 中，我们可以创建`spl_autoload_register`函数，它将自动处理所需的文件。

以下是基于 PHP 手册中的示例的示例实现：

```php
<?php 
/** 
 * After registering this autoload function with SPL, the following line 
 * would cause the function to attempt to load the \Newsletter\Qux class 
 * from /path/to/project/src/Newsletter/Qux.php: 
 *  
 *      new \Newsletter\Qux; 
 *       
 * @param string $class The fully-qualified class name. 
 * @return void 
 */ 
spl_autoload_register(function ($class) { 
    // project-specific namespace prefix 
    $prefix = 'Newsletter'; 
    // base directory for the namespace prefix 
    $base_dir = __DIR__ . '/src/'; 
    // does the class use the namespace prefix? 
    $len = strlen($prefix); 
    if (strncmp($prefix, $class, $len) !== 0) { 
        // no, move to the next registered autoloader 
        return; 
    } 
    // get the relative class name 
    $relative_class = substr($class, $len); 
    // replace the namespace prefix with the base directory,               //replace namespace 
    // separators with directory separators in the relative class      //name, append 
    // with .php 
    $file = $base_dir . str_replace('', '/', $relative_class) . '.php'; 
    // if the file exists, require it 
    if (file_exists($file)) { 
        require $file; 
    } 
}); 

```

使用上述代码，我们现在需要创建一个`src`目录，并在应用程序中使用此分隔符`\\`约定来分隔文件夹结构。

使用此示例意味着我们需要将数据库类文件`DB.class.php`放在`src`文件夹中，并将文件名重命名为`DB.php`。

这样做是为了当您在另一个 PHP 脚本中指定要使用`DB`类时，PHP 将在后台自动执行`require src/DB.php`。

继续使用我们的示例`DbContainer`，我们需要以某种方式将所有配置信息（即数据库名称、用户名和密码）传递到`DbContainer`中。

让我们简单地创建一个名为`dbconfig.php`的文件，其中包含数据库详细信息并将其作为对象返回，并要求它：

```php
//sample dbconfig.php 
return array('server' => 'localhost', 
  'username' => 'root', 
  'password => '', 
  'dbname' => 'newsletterdb' 
); 

```

在我们的`DbContainer`类中，让我们创建一个`loadConfig()`函数，从`dbconfig.php`文件中读取，并实例化一个数据库连接：

```php
Class DbContainer { 
public function  loadConfig ($filePath) { 

   if($filePath) { 
     $config = require($filePath); 
     return $config; //contains the array  
   } 

} 

```

现在我们需要创建一个`connect()`方法，这将使我们能够简单地连接到 MySQL 数据库并仅返回连接：

```php
Class DB { 
 //... 
public function connect($server, $username, $password, $dbname) { 
   $this->connection = new MySQLI($server, $username, $password, $dbname); 
     return $this->connection; 
} 
} 

```

通过不将文件名硬编码到我们的函数中，我们使我们的函数更加灵活。在调用`loadConfig()`时，我们需要将`config`文件的路径放入。

我们还使用了`$this`关键字，这样每当我们需要引用`DB`类中的其他函数时，我们只需在自动加载程序加载并实例化`DB`类后调用`$DB->nameOfMethod(someParams)`。

有了这个，我们现在可以轻松地更改`config`文件的路径，以防我们将`config`文件移动到其他路径，例如，到一个通过 Web 直接访问的文件夹。

然后，我们可以轻松地使用这个函数，并在一个单独的类中生成一个数据库实例，例如，在我们的`Newsletter`类中，我们现在可以引用`DB`类连接的一个实例，并在`Newsletter`类中实例化它。

现在我们完成了这一步，我们应该简单地创建一个 Bootstrap 文件，加载`spl_autoload_register`函数和使用`dbContainer`连接到数据库。让我们将文件命名为`bootstrap.php`，它应该包含以下内容：

```php
require('spl_autoloader_function.php'); 

$dbContainer = new \DBContainer; //loads our DB from src folder, using the spl_autoload_functionabove. 

$dbConfig = $db->getConfig('dbconfig.php'); 

$dbContainer = getDB($dbConfig); //now contains the array of database configuration details 

```

下一步是使用以下代码连接到数据库：

```php
$DB = new \DB;  
$DBConn = $DB->connect($dbContainer['server'],$dbContainer['username'],$dbContainer['password'],$dbContainer['dbname']); 

```

当我们都连接到数据库之后，我们需要重写我们的授权查询，以使用新初始化的类。

让我们在我们的`DB`类中创建一个简单的`select_where`方法，然后从`Authorization`类中调用它：

```php
public function select_where($table, $where_clause) { 
   return $this->db->query("SELECT * FROM ". $table." WHERE " . $where_clause); 
} 

```

`Authorization`类现在如下所示：

```php
Class Authorization { 
    //this is used to get the database class into Authorization  
    Public function instantiateDB($dbInstance){ 
       $this->db = $dbInstance; 
    } 

    public function verify($email, $password) { 
         //check for the $email and password encrypted with bcrypt 
         $bcrypt_options = [ 
            'cost' => 12, 
            'salt' => 'secret' 
         ]; 
         $password_hash = password_hash($password, PASSWORD_BCRYPT, $bcrypt_options); 
         //select with condition 
         $this->db->select_where('users', "email = '$email' AND password = '$password_hash'"); 
         if($result = $this->db->query($q)) { 
                     while ($obj = results->fetch_object()) { 
                           $user_id = $obj->id; 
} 

         } else { 
   $user_id = null; 
} 
         $result->close(); 
         $this->db->close(); 
         return $user_id; 

    } 
} 

```

## 为会员创建社交登录

为了让更多人轻松订阅，我们将实现一种方式，让 Facebook 用户可以简单地登录并订阅我们的通讯，而无需输入他们的电子邮件地址。

通过**Oauth**登录 Facebook 通过生成应用程序认证令牌开始。第一步是转到[`developers.facebook.com/`](https://developers.facebook.com/)。

您应该看到您的应用程序列表，或者点击应用程序进行创建。您应该看到类似以下截图的内容：

![为会员创建社交登录](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_03_001.jpg)

您应该首先创建一个应用程序，并且可以通过访问应用程序创建页面来获取您的应用程序 ID 和应用程序密钥，类似于以下截图：

![为会员创建社交登录](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_03_002.jpg)

在创建新应用程序时，Facebook 现在包括了一种测试应用程序 ID 的方法。

它看起来像这样：

![为会员创建社交登录](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_03_003.jpg)

这是为了测试应用程序 ID 是否有效。这是可选的，您可以跳过这一步，只需将应用程序 ID 和应用程序密钥的值插入到前面截图中显示的代码中。

现在让我们创建`fbconfig.php`文件，其中将包含一种使用 Facebook SDK 库启用会话的方法。

`fbconfig.php`脚本将包含以下内容：

```php
<?php 
session_start(); 
$domain = 'http://www.socialexample.info'; 
require_once 'autoload.php'; 

use FacebookFacebookSession; 
use FacebookFacebookRedirectLoginHelper; 
use FacebookFacebookRequest; 
use FacebookFacebookResponse; 
use FacebookFacebookSDKException; 
use FacebookFacebookRequestException; 
use FacebookFacebookAuthorizationException; 
use FacebookGraphObject; 
use FacebookEntitiesAccessToken; 
use FacebookHttpClientsFacebookCurlHttpClient; 
use FacebookHttpClientsFacebookHttpable; 

// init app with app id and secret (get from creating an app) 
$fbAppId = '123456382121312313'; //change this. 
$fbAppSecret = '8563798aasdasdasdweqwe84'; 
FacebookSession::setDefaultApplication($fbAppId, $fbAppSecret); 
// login helper with redirect_uri 
    $helper = new FacebookRedirectLoginHelper($domain . '/fbconfig.php' ); 
try { 
  $session = $helper->getSessionFromRedirect(); 
} catch( FacebookRequestException $ex ) { 
echo "Hello, sorry but we've encountered an exception and could not log you in right now"; 
} catch( Exception $ex ) { 
  // Tell user something has happened 
  echo "Hello, sorry but we could not log you in right now";       
} 
// see if we have a session 
if ( isset( $session ) ) { 
  // graph api request for user data 
  $request = new FacebookRequest( $session, 'GET', '/me' ); 
  $response = $request->execute(); 
  // get response 
//start a graph object with the user email 
  $graphObject = $response->getGraphObject(); 
  $id = $graphObject->getProperty('id');  
  $fullname = $graphObject->getProperty('name');  
  $email = $graphObject->getProperty('email'); 

     $_SESSION['FB_id'] = $id;            
     $_SESSION['FB_fullname'] = $fullname; 
     $_SESSION['FB_email'] =  $email; 

//save user to session 
     $_SESSION['UserName'] = $email; //just for demonstration purposes 
//redirect user to index page        
    header("Location: index.php"); 
} else { 
  $loginUrl = $helper->getLoginUrl(); 
 header("Location: ".$loginUrl); 
} 
?> 

```

在这里，我们基本上通过`session_start()`开始一个会话，并通过将其保存到一个变量中设置我们网站的域。然后自动加载 FB SDK，这将需要 Facebook 访问其 API 所需的文件和类来访问。

然后，我们使用`use`关键字在其他 Facebook SDK 类上设置了几个依赖项。我们使用我们的应用程序 ID 和应用程序密钥设置了`facebookSession`类，然后尝试通过调用`getSessionfromRedirect()`方法启动会话。

如果有任何错误被捕获尝试启动会话，我们只需让用户知道我们无法登录他，但如果一切顺利进行，我们将以用户的电子邮件开始一个图形对象。

为了演示目的，我们保存一个用户名，实际上是用户的电子邮件地址，一旦我们通过 Facebook 图表获取了电子邮件。

无论如何，我们将通过检查他们的电子邮件地址对每个人进行身份验证，并且为了让用户更容易登录，让我们只将他们的电子邮件存储为用户名。

我们需要用`index.php`完成我们的网站，向用户展示我们网站内部的内容。我们在从 Facebook 页面登录后，将用户重定向到`index.php`页面。

现在我们将保持简单，并从登录的用户的 Facebook 个人资料中显示全名。我们将添加一个注销链接，以便用户有注销的选项：

```php
<?php 
session_start();  
?> 
<!doctype html> 
<html > 
  <head> 
    <title>Login to SocialNewsletter.com</title> 
<link href=" https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" rel="stylesheet">  
 </head> 
  <body> 
  <?php if ($_SESSION['FB_id']): ?>      <!--  After user login  --> 
<div class="container"> 
<div class="hero-unit"> 
  <h1>Hello <?php echo $_SESSION['UserName']; ?></h1> 
  <p>How to login with PHP</p> 
  </div> 
<div class="span4"> 
 <ul class="nav nav-list"> 
<li class="nav-header">FB ID: <?php echo $_SESSION['FB_id']; ?></li> 
<li> Welcome <?php echo $_SESSION['FB_fullName']; ?></li> 
<div><a href="logout.php">Logout</a></div> 
</ul></div></div> 
    <?php else: ?>     <!-- Before login -->  
<div class="container"> 
<h1>Login with Facebook</h1> 
           Not Connected with Facebook. 
<div> 
      <a href="fbconfig.php">Login with Facebook</a></div> 
      </div> 
    <?php endif ?> 
  </body> 
</html> 

```

登录后，我们只需为用户显示仪表板。我们将在下一节讨论如何为用户创建基本仪表板。

## 会员仪表板

最后，当会员登录我们的应用程序时，他们现在可以使用会员订阅页面订阅通讯。让我们首先构建用于存储会员详细信息和他们订阅的数据库。`member_details`表将包括以下内容：

+   `firstname`和`lastname`：用户的真实姓名

+   `email`：能够给用户发送电子邮件

+   `canNotify`：布尔值（true 或 false），如果他们同意通过电子邮件接收有关其他优惠的通知

### 提示

关于 MySQL 中的布尔类型有趣的是，当您创建使用布尔值（true 或 false）的字段时，MySQL 实际上只将其别名为`TINYINT(1)`。布尔基本上是 0 表示 false，1 表示 true。有关更多信息，请参阅[`dev.mysql.com/doc/refman/5.7/en/numeric-type-overview.html`](http://dev.mysql.com/doc/refman/5.7/en/numeric-type-overview.html)。

`member_details`表将处理此事，并将使用以下 SQL 代码创建：

```php
CREATE TABLE member_details(  
  id INT(11) PRIMARY KEY AUTO_INCREMENT, 
  firstname VARCHAR(255), 
  lastname VARCHAR(255), 
  email VARCHAR(255), 
  canNotify TINYINT(1), 
  member_id INT(11) 
); 

```

登录时，我们的会员将存储在`users`表中。让我们使用以下 SQL 代码创建它：

```php
CREATE TABLE users ( 
   id INT(11) PRIMARY KEY AUTO_INCREMENT 
   username VARCHAR(255), 
   password VARCHAR(255), 
); 

```

现在，构建一个视图，向我们的会员展示我们拥有的所有不同订阅。我们通过检查`subscriptions`表来实现这一点。`subscriptions`表模式定义如下：

+   `id Int(11)`：这是`subscriptions`表的主键，并设置为`AUTO_INCREMENT`

+   `newsletter_id Int(11)`：这是他们订阅的`newsletter_id`

+   `active BOOLEAN`：这表示用户当前是否订阅（默认为 1）

使用 SQL，它将如下所示：

```php
CREATE TABLE subscriptions ( 
  `id` INT(11) PRIMARY KEY AUTO_INCREMENT, 
  `newsletter_id` INT(11) NOT NULL, 
  `member_id` INT(11) NOT NULL, 
  `active` BOOLEAN DEFAULT true 
); 

```

我们还需要创建`newsletters`表，其中将以 JSON 格式保存所有通讯、它们的模板和内容。通过在我们的数据库中使用 JSON 作为存储格式，现在应该很容易从数据库中获取数据并将 JSON 解析为适当的值插入到我们的模板中。

由于我们的通讯将存储在数据库中，我们需要为其创建适当的 SQL 模式。设计如下：

+   `Id INT(11)`：在数据库中索引我们的通讯

+   `newsletter_name（文本）`：我们通讯的标题

+   `newsletter_count INT(11)`：记录我们特定通讯的版本

+   `Status（字符串）`：记录我们的通讯的状态，是否已发布、未发布或待发布

+   `Slug（字符串）`：能够在我们的社交通讯网站上使用浏览器查看通讯

+   `Template（文本）`：存储 HTML 模板

+   `Content（文本）`：存储将进入我们的 HTML 模板的数据

+   发布日期（日期）：记录发布日期

+   `Created_at（日期）`：记录通讯首次创建的时间

+   `Updated_at（日期）`：记录上次有人更新通讯的时间

其 SQL 如下：

```php
CREATE TABLE newsletters ( 
id INT(11) PRIMARY KEY AUTO_INCREMENT, 
newsletter_name (TEXT), 
newsletter_count INT(11) NOT NULL DEFAULT '0', 
marketer_id INT(11) NOT NULL, 
is_active TINYINT(1), 
created_at DATETIME, 

); 

```

当用户取消订阅时，这将帮助指示他们先前订阅了此通讯。这就是为什么我们将存储一个`active`字段，以便当他们取消订阅时，而不是删除记录，我们只需将其设置为 0。

`marketer_id`将在未来的管理部分中使用，其中我们提到将负责管理新闻通讯订阅的人员。

新闻通讯也可能有许多出版物，这些出版物将是实际发送给每个订阅的新闻通讯。以下 SQL 代码是用来创建出版物的：

```php
CREATE TABLE publications ( 
  newsleterId INT(11) PRIMARY KEY AUTO_INCREMENT, 
  status VARCHAR(25), 
  content TEXT, 
  template TEXT, 
  sent_at DATETIME, 
  created_at DATETIME, 
); 

```

现在让我们在我们的`Newsletter`类中构建方法，以选择已登录会员的订阅以显示到我们的仪表板：

```php
Class Dashboard { 
  public function getSubscriptions($member_id) { 
  $query = $db->query("SELECT * FROM subscriptions, newsletters WHERE subscriptions.member_id ='". $member_id."'"); 
  if($query->num_rows() > 0) { 
      while ($row = $result->fetch_assoc()) { 
          $data  = array(  
            'name' => $row->newsletter_name,  
            'count' => $row->newsletter_count, 
            'mem_id' => $row->member_id,  
            'active' => $row->active 
         ); 
      } 
      return $data; 
  }  
} 
} 

```

从上述代码中，我们只是创建了一个函数，用于获取给定会员 ID 的订阅。首先，我们创建了`"SELECT * FROM subscriptions, newsletters WHERE subscriptions.member_id ='". $member_id."`查询。之后，我们使用 MySQLi 结果对象的`fetch_assoc()`方法循环遍历查询结果。现在我们已经将其存储在`$data`变量中，我们返回该变量，并在以下代码中通过调用以下函数在表中显示数据：

```php
 $member_id = $_SESSION['member_id']; 
 $dashboard = new Dashboard; 
 $member_subscriptions = $dashboard->getSubscriptions($member_id); 
 ?> 
  <table> 
    <tr> 
      <td>Member Id</td><td>Newsletter Name</td><td>Newsletter count</td><td>Active</td> 
     </tr> 
<?php 
 foreach($member_subscriptions as $subs) { 
    echo '<tr> 
     <td>'. $subs['mem_id'] . '</td>' .  
     '<td>' . $subs['name'].'</td>' .  
     '<td>' . $subs['count'] . '</td>'. 
     '<td>' . $subs['active'] . '</td> 
     </tr>'; 
 } 
 echo '</table>'; 

```

## 营销人员仪表盘

我们的营销人员，他们管理自己拥有的每个新闻通讯，将能够登录到我们的系统，并能够看到有多少会员订阅了他们的电子邮件地址。

这将是一个管理员系统，使营销人员能够更新会员记录，查看最近的订阅，并允许营销人员向其新闻通讯的任何会员发送自定义电子邮件。

我们将有一个名为`marketers`的表，其中将包含以下字段：

+   `id`：用于存储索引

+   营销人员的姓名：用于存储营销人员的姓名

+   营销人员的电子邮件：用于存储营销人员的电子邮件地址

+   营销人员的密码：用于存储营销人员的登录密码

我们用于创建上述字段的 SQL 很简单：

```php
CREATE TABLE marketers ( 
id INT(11) AUTO_INCREMENT, 
marketer_name VARCHAR(255) NOT NULL, 
marketer_email VARCHAR(255) NOT NULL, 
marketer_password VARCHAR(255) NOT NULL, 

PRIMARY KEY `id`  
); 

```

在另一个表中，我们将定义营销人员及其管理的新闻通讯的多对多关系。

我们需要一个`id`作为索引，拥有新闻通讯的营销人员的 ID，以及营销人员拥有的新闻通讯的 ID。

创建此表的 SQL 如下：

```php
CREATE TABLE newsletter_admins ( 
  Id INT(11) AUTO_INCREMENT, 
  marketer_id INT(11) , 
  newsletter_id INT(11), 
  PRIMARY KEY `id`, 
); 

```

现在让我们构建一个查询，以获取他们拥有的新闻通讯的管理员。这将是一个简单的类，我们将引用所有我们的数据库函数：

```php
<?php  
class NewsletterDb { 
public $db; 

function __construct($dbinstance) { 
$this->db = $dbinstance; 
} 

//get admins = marketers 
public function get_admins ($newsletter_id) { 
$query = "SELECT * FROM newsletter_admins LEFT JOIN marketers ON marketers.id = newsletter_admins.admin_id.WHERE newsletters_admins.newsletter_id = '".$newsletter_id."'"; 
  $this->db->query($query); 
} 
} 

```

### 管理营销人员的管理系统

我们需要一种方法让营销人员登录并通过密码进行身份验证。我们需要一种方法让管理员创建帐户并注册营销人员及其新闻通讯。

让我们首先构建这部分。

在我们的管理视图中，我们将需要设置一个默认值，并要求对执行的每个操作进行身份验证密码。这是我们不需要存储在数据库中的东西，因为只会有一个管理员。

在我们的`config`/`admin.php`文件中，我们将定义用户名和密码如下：

```php

<?php 
$admin_username = 'admin'; 
$password = 'test1234'; 
?> 

```

然后我们只需在我们的登录页面`login.php`中包含文件。我们将简单地检查它。登录页面的代码如下：

```php
<html> 
<?php  
if(isset($_POST['username']) && isset($_POST['password'])) { 
  //check if they match then login 
  if($_POST['username'] == $admin_username  
    && $_POST['password'] == $password) { 
   //create session and login 
   $_SESSION['logged_in'] = true; 
   $_SESSION['logged_in_user'] = $admin_username; 
      header('http://ourwebsite.com/admin/welcome_dashboard.php'); 
 } 
 ?> 
} 
</html> 

```

请注意，我们必须根据我们正在开发的位置正确设置我们的网站 URL。在上面的示例中，页面将在登录后重定向到[`ourwebsite.com/admin/welcome_dashboard.php`](http://ourwebsite.com/admin/welcome_dashboard.php)。我们可以创建变量来存储域和要重定向到的 URL 片段，以便这可以是动态的；请参阅以下示例：

```php
$domain = 'http://ourwebsite.com'; 
$redirect_url = '/admin/welcome_dashboard.php'; 
header($domain . $redirect_url); 

```

一旦登录，我们将需要构建一个简单的 CRUD（创建、读取、更新、删除）系统来管理将管理他们的新闻通讯的营销人员。

以下是能够获取营销人员和他们管理的新闻通讯列表的代码：

```php
Function get_neewsletter_marketers() { 
  $q = "SELECT * FROM marketers LEFT JOIN newsletters '; 
  $q .= "WHERE marketers.id = newsletters.marketer_id"; 

  $res = $db->query($q); 

  while ($row = $res->fetch_assoc()) { 
   $marketers = array( 
     'name' => $row['marketer_name'], 
     'email' => $row['marketer_email'], 
     'id' => $row['marketer_id'] 
    ); 
  } 
  return $marketers; 
} 

```

我们需要添加一种方法来编辑、创建和删除营销人员。让我们创建一个`dashboard`/`table_header.php`来包含在我们脚本的顶部。

以下是`table_header.php`代码的样子：

```php
<table> 
<tr> 
 <th>Marketer Email</th> 
  <th>Edit</th> 
 <th>Delete</th> 
</tr> 

```

现在我们将创建一个`for()`循环来循环遍历每个营销人员。让我们创建一种方法来选择我们数据库中的所有营销人员。首先，让我们调用我们的函数来获取数据：

```php
$marketrs = get_newsletter_marketers(); 

```

然后让我们使用`foreach()`循环来循环遍历所有营销人员：

```php
foreach($marketers as $marketer) { 
  echo '<tr><td>'. $marketer['email'] .'</td> 
   <td><a href="edit_marketer.php?id='. $marketer['id'].'">Edit</a></td> 
  <td><a href="delete_marketer.php">delete</td> 
  </tr>'; 
} 
echo '</table>'; 

```

然后我们用`</table>`为表结束代码。

让我们创建`delete_marketer.php`脚本和`edit_marketer.php`脚本。以下将是删除脚本：

```php
function delete_marketer($marketer_id) { 
  $q = "DELETE FROM marketers WHERE marketers.id = '" .   $marketer_id . "'"; 
   $this->db->query($q); 
} 
$marketer_id = $_GET['id']; 
delete_marketer($marketer_id); 

```

这是由一个表单组成的编辑脚本，一旦提交将更新数据：

```php
if(empty($_POST['submit'])) { 
  $marketer_id = $_GET['id']; 
  $q = "SELECT * FROM marketers WHERE id = '" . $marketer_id."'"; 

 $res = $db->query($q); 

  while ($row = $res->fetch_assoc()) { 
   $marketer = array( 
     'name' => $row['marketer_name'], 
     'email' => $row['marketer_email'], 
     'id' => $row['id'] 
    ); 
  } 

  ?> 
  <form action="update_marketer.php" method="post"> 
   <input type="hidden" name="marketer_id" value="<?php echo $marketer['id'] ?>"> 
   <input type="text" name="marketer_name" value="<?php echo $marketer['name'] ?>"> 
   <input type="text" name="marketer_email" value="<?php echo $marketer['email'] ?>"> 
  <input type="submit" name="submit" /> 
</form> 
  <?php 

  } else { 
     $q = "UPDATE marketers SET marketer_name='" . $_POST['marketer_name'] . ", marketer_email = '". $_POST['marketer_email']."' WHERE id = '".$_POST['marketer_id']."'"; 
   $this->db->query($q); 
   echo "Marketer's details has been updated"; 
  } 
?> 

```

## 我们的通讯的自定义模板

每个营销人员都需要制定他们的通讯。在我们的情况下，我们可以允许他们创建一个简单的侧边栏通讯和一个简单的自上而下的通讯。为了构建一个简单的侧边栏，我们可以创建一个 HTML 模板，看起来像下面这样：

```php
<html> 
<!doctype html> 

<sidebar style="text-align:left"> 
{{MENU}} 
</sidebar> 

<main style="text-align:right"> 
   {{CONTENT}} 
</main> 
</html> 

```

在之前的代码中，我们使用内联标签样式化 HTML 电子邮件，因为一些电子邮件客户端不会渲染从我们 HTML 外部引用的样式表。

我们可以使用**正则表达式**来替换`{{MENU}}`和`{{CONTENT}}`模式，以填充数据。

我们的数据库将以 JSON 格式存储内容，一旦解析 JSON，我们将得到内容和菜单数据，然后插入到它们各自的位置。

在我们的数据库中，我们需要添加`newsletter_templates`表。以下是我们将如何创建它：

```php
CREATE TABLE newsletter_templates ( 
 Id INT(11) PRIMARY KEY AUTO_INCREMENT, 
Newsletter_id INT(11) NOT NULL, 
   Template TEXT NOT NULL, 
   Created_by INT(11) NOT NULL   
) ENGINE=InnoDB; 

```

有了模板之后，我们需要一种方法让营销人员更新模板。

从仪表板上，我们显示通讯的模板列表。

让我们按照以下方式创建表单：

```php
$cleanhtml = htmlentities('<html> 
<!doctype html> 

<sidebar style="text-align:left"> 
{{MENU}} 
</sidebar> 

<main style="text-align:right"> 
   {{CONTENT}} 
</main> 
</html> 
'); 
<form> 
   <h2>Newsletter Custom Template</h2> 
  <textarea name="customtemplate"> 
<?php echo $cleanhtml; ?> 
</textarea> 
  <input type="submit" value="Save Template" name="submit"> 
  </form> 

```

我们还通过向`textarea`添加值来填充它。请注意，在之前的代码中，我们需要首先使用`htmlentities`清理模板的 HTML 代码。这是因为我们的 HTML 可能被解释为网页的一部分，并在浏览器渲染时引起问题。

我们现在已经准备好发送实际的通讯了。为了发送通讯，我们需要创建一个脚本，循环遍历通讯中的所有成员，然后简单地使用 PHP 邮件功能发送给他们。

使用 PHP 邮件功能，我们只需要循环遍历我们数据库中的所有通讯成员。

这就是那个脚本的样子：

```php
$template = require('template.class.php'); 
$q = "SELECT * FROM newsletter_members WHERE newsletter_id = 1"; //if we're going to mail newsletter #1  
$results = $db->query($q); 
While ($rows =$results->fetch_assoc() ) { 
  //gather data  
  $newsletter_title = $row['title']; 
  $member_email = $row['template']; 
  $menu = $row['menu']; //this is a new field to contain any menu html 
  $content = $row['content']; 
  $content_with_menu = $template->replace_menu($menu, $content); 
  $emailcontent = $template->         replace_contents($content,$content_with_menu); 
  //mail away! 
  mail($member_email, 'info@maillist.com', $newsletter_title ,$email_content); 
} 

```

我们需要完成`replace_menu`和`replace_contents`函数。让我们简单地构建文本替换函数，用于替换我们在之前的代码中已经获取的内容。数据来自数据库中的通讯表：

```php
class Template { 
   public function replace_menu($menu, $content) { 
     return  str_replace('{{MENU}}', $menu, $content); 
   } 
   public function replace_contents ($actualcontent, $content) { 
    return str_replace('{{CONTENT}}', $actualcontent,  $content); 
   }  
} 

```

请注意，我们修改了我们的表，为通讯中添加了菜单。这个菜单必须由用户创建，并使用 HTML 标记。它基本上是一个 HTML 链接列表。菜单的正确标记应该如下所示：

```php
<ul> 
  <li><a href="http://someUrl.com">some URL</a></li> 
<li><a href="http://someNewUrl.com">some new URL</a></li> 
<li><a href="http://someOtherUrl.com">some other URL</a></li> 
</ul> 

```

## 链接跟踪

对于我们的链接跟踪系统，我们需要允许营销人员嵌入链接，实际上通过我们的系统传递，以便我们跟踪链接的点击次数。

我们将创建一个服务，自动将我们输入的链接缩短为随机哈希。URL 看起来像`http://example.com/link/xyz123`，哈希`xyz123`将存储在我们的数据库中。当用户访问链接时，我们将匹配链接。

让我们创建链接表，并创建一个函数来帮助我们生成缩短链接。至少，我们需要能够存储链接的标题、实际链接、缩短链接，以及创建链接的人，以便我们可以将其放在营销人员的仪表板上。

链接表的 SQL 如下所示：

```php
CREATE TABLE links ( 
   id INT(11) PRIMARY KEY AUTO_INCREMENT, 
   link_title TEXT NOT NULL, 
   actual_link TEXT, 
   shortened_link VARCHAR(255), 
   created DATETIME, 
   created_by INT(11) 
); 

```

现在让我们创建以下函数，它将生成一个随机哈希：

```php
public function createShortLink($site_url,$title, $actual_url,$created_by) { 
    $created_date = date('Y-m-d H:i:s'); 
  $new_url = $site_url . "h?=" . md5($actual_url); 
  $res = $this->db->query("INSERT INTO links VALUES (null, $title ,'". $actual_url. "', '". $new_url.", '". $created_date."','".$created_by."'"),; 
  )); 
   return $res; 
} 

```

我们还需要存储链接的点击次数。我们将使用另一个表，将`link_id`链接到点击次数，每当有人使用缩短链接时，我们将更新该表：

```php
CREATE TABLE link_hits ( 
   link_id INT(11), 
   num_hits INT(11) 
); 

```

我们不需要对之前的 SQL 表进行索引，因为我们不需要在其上进行快速搜索。每次生成新的 URL 时，我们应该将表填充为`num`默认为 0：

在`createShortLink`函数中添加以下函数：

```php
$res = $this->db->query("INSERT INTO links VALUES (null, '$actual_url',$title, '$new_url', '$created_date', '$created_by'"); 

$new_insert_id = $this->db->insert_id; 

$dbquery = INSERT INTO link_hits VALUES($new_insert_id,0); 

$this->db->query($dbquery); 

```

`insert_id`是 MySQL 最后插入记录的 ID。它是一个函数，每次添加新行时都会返回新生成的 ID。

让我们生成包含两个函数的链接点击类，一个用于初始化数据库，另一个用于在用户点击链接时更新`link_hits`表：

```php
Class LinkHit {       

     Public function __construct($mysqli) { 
          $this->db = $mysqli; 
      } 

   public function  hitUpdate ($link_id) { 

  $query = "UPDATE link_hits SET num_hits++ WHERE link_id='".    $link_id. "'"; 

   //able to update 
     $this->db->query($query)       
   } 

   Public function checkHit ($shorturl) { 
   $arrayUrl = parse_url($shortUrl); 
parse_str($parts['query'],$query); 
$hash = $query['h'];  

   $testQuery = $this->db->query("SELECT id FROM links WHERE shortened_link LIKE '%$hash%'"); 
   if($this->db->num_rows > 0) { 
         while($row = $testQuery->fetch_array() ) { 
   return $row['id']; 
          } 
   } else { 
     echo "Could not find shorted link"; 
     return null; 
  } 
} 

//instantiating the function: 
$mysqli = new mysqli('localhost','test_user','test_password','your_database'); 
$Link = new LinkHit($mysqli); 
$short_link_id = $Link->checkHit("http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"); 

if($short_link_id !== null) { 
  $link->hitUpdate($isShort); 
} 

```

为了让我们的营销人员查看链接，我们需要在我们的门户网站上的`links`页面上显示他们的链接。

我们创建用于检查链接及其点击次数的功能，这是归因于已登录的管理员用户：

```php
$user_id = $_SESSION['user_id']; 
$sql = "SELECT * FROM links LEFT JOIN link_hits ON links.id = link_hits.link_id WHERE links.created_by='" . $user_id. "'"; 
$query = $mysqli->query($sql); 
?> 
<table> 
<tr> 
<td>Link id</td><td>Link hits</td></tr> 
<?php 
while($obj = $query->fetch_object()) { 
  echo '<tr><td>'.$obj->link.'</td> 
<td>' . $obj->link_hits.'</td></tr></tr>'; 
} 
?> 
</table> 

```

在上述代码中，我们只是通过检查变量`$_SESSION['user_id']`获取了已登录用户的 ID。然后我们通过执行字符串变量`$SQL`执行了一个 SQL 查询。之后，我们循环遍历结果，并将结果显示在 HTML 表中。请注意，当我们显示永久的 HTML 标记时，例如表的开头、标题和`</table>`标记的结束时，我们退出 PHP 代码。

PHP 在不使用 echo 语句时性能略有提高，这就是 PHP 脚本的美妙之处，您真的可以进入 PHP 部分，然后进入代码中的 HTML 部分。您对这个想法的美感可能有所不同，但我们只是想展示 PHP 在这个练习中可以做什么。

## 支持的 AJAX 套接字聊天

该系统允许订阅者联系特定通讯组的管理员。它将只包含一个联系表单。此外，我们需要实现一种实时向管理员发送通知的方式。

我们将基本上为管理员添加一个套接字连接，以便每当有人发送查询时，它将在营销人员的仪表板上闪烁通知。

这对于**socket.io**和一个名为 WebSockets 的浏览器技术来说非常简单。

### socket.io 简介

使用 socket.io，我们不需要创建用于定期检查服务器是否有事件的代码。我们只需通过 AJAX 传递用户输入的数据，并通过发出事件来触发套接字的监听器。它提供了长轮询和通过 WebSockets 进行通信，并得到了现代 Web 浏览器的支持。

### 注意

WebSockets 扩展了通过浏览器建立套接字连接的概念。要了解有关 WebSockets 的更多信息，请访问[`www.html5rocks.com/en/tutorials/websockets/basics/`](http://www.html5rocks.com/en/tutorials/websockets/basics/)。

socket.io 网站上的示例代码只包括`socket.io.js`脚本：

```php
<script src="socket.io/socket.io.js"></script> 

```

我们的 PHP Web 服务器将使用一个名为**Ratchet**的东西，它在[`socketo.me`](http://socketo.me)上有一个网站。它基本上允许我们为 PHP 使用 WebSockets。

这是他们的网站：

![socket.io 简介](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_03_004.jpg)

Ratchet 只是一个工具，允许 PHP 开发人员“*在 WebSockets 上创建实时的、双向的应用程序*”。通过创建双向数据流，它允许开发人员创建实时聊天和其他实时应用程序等东西。

让我们通过按照他们在[`socketo.me/docs/hello-world`](http://socketo.me/docs/hello-world)上的教程开始。

使用 Ratchet，我们需要安装**Composer**并将以下内容添加到我们项目目录中的`composer.json`文件中：

```php
{ 
    "autoload": { 
        "psr-0": { 
            "MyApp": "src" 
        } 
    }, 
    "require": { 
        "cboden/ratchet": "0.3.*" 
    } 
} 

```

如果您之前有使用 Composer 的经验，基本上它所做的就是在编写需要自动加载的脚本的路径时使用`psr-0`标准。然后我们在同一目录中运行`composer install`。在设置好 Ratchet 之后，我们需要设置处理某些事件的适当组件。

我们需要创建一个名为`SupportChat`的文件夹，并将`Chat.php`放在其中。这是因为在之前的`composer.json`文件中使用 psr-0 时，它期望`src`目录内有一个目录结构。

让我们创建一个包含我们需要实现的存根函数的类：

```php
namespace SupportChat; 
use Ratchet\MessageComponentInterface; 
use Ratchet\ConnectionInterface; 

class SupportChat implements MessageComponentInterface { 
  Protected $clients; 
  Public function __construct() { 
    $this->clients = new \SplObjectStorage; 
  } 
} 

```

我们需要声明`$clients`变量来存储将连接到我们聊天应用程序的客户端。

让我们实现客户端打开连接时的接口：

```php
Public function onOpen(ConnectionInterface $conn) { 
  $this->clients->attach($conn); 
  echo "A connection has been established"; 
} 

```

现在让我们创建`onMessage`和`onClose`方法如下：

```php
Public function onMessage (ConnectionInterface $from, $msg) { 
 foreach ($this->clients as $client) { 
        if ($from !== $client) { 
            $client->send($msg); 
        } 
    } 
} 

public function onClose(ConnectionInterface $conn) { 
$this->clients->detach($conn); 
} 

```

让我们也创建一个用于处理错误的`onError`方法如下：

```php
public function onError (ConnectionInterface $conn) { 
$this->clients->detach($conn); 
} 

```

现在我们需要实现应用程序的客户端（浏览器）部分。

在您的`htdocs`或`public`文件夹中创建一个名为`app.js`的文件，其中包含以下代码：

```php
var messages = []; 

// connect to the socket server 
var conn = new WebSocket('ws://localhost:8088'); 
conn.onopen = function(e) { 
   console.log('Connected to server:', conn); 
} 

conn.onerror = function(e) { 
   console.log('Error: Could not connect to server.'); 
} 

conn.onclose = function(e) { 
   console.log('Connection closed'); 
} 

// handle new message received from the socket server 
conn.onmessage = function(e) { 
   // message is data property of event object 
   var message = JSON.parse(e.data); 
   console.log('message', message); 

   // add to message list 
   var li = '<li>' + message.text + '</li>'; 
   $('.message-list').append(li); 
} 

// attach onSubmit handler to the form 
$(function() { 
   $('.message-form').on('submit', function(e) { 
         // prevent form submission which causes page reload 
         e.preventDefault(); 

         // get the input 
         var input = $(this).find('input'); 

         // get message text from the input 
         var message = { 
               type: 'message', 
               text: input.val() 
         }; 

         // clear the input 
         input.val(''); 

         // send message to server 
         conn.send(JSON.stringify(message)); 
   }); 
}); 

```

我们需要创建用于上述代码的 HTML。我们应该将文件命名为`app.js`。现在，让我们实现一个简单的输入文本，让用户输入他们的消息：

```php
<!DOCTYPE html> 
<html> 
<head> 
   <title>Chat with Support</title> 
   <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.3/jquery.js"></script> 
   <script src="app.js"></script> 
</head> 
<body> 

   <h1>Chat with Support</h1> 

   <h2>Messages</h2> 
   <ul class="message-list"></ul> 
   <form class="message-form"> 
         <input type="text" size="40" placeholder="Type your message here" /> 
         <button>Send message</button> 
   </form> 
</body> 
</html> 

```

`App.js`是我们之前编写的 JavaScript 代码应该放置的地方。我们还需要创建一个 WebSocket 服务器来处理端口`8088`上的 WebSocket：

```php

<?php 
// import namespaces 
use Ratchet\Server\IoServer; 
use Ratchet\WebSocket\WsServer; 
use SupportChat\Chat; 

// use the autoloader provided by Composer 
require dirname(__DIR__) . '/vendor/autoload.php'; 

// create a websocket server 
$server = IoServer::factory( 
    new WsServer( 
        new Chat() 
    ) 
    , 8088 
); 

$server->run(); 

```

我们的聊天应用现在已经准备好供公众使用。但是，我们需要启动我们的聊天服务器，通过`php bin/server.php`启动它来处理 WebSockets。

请注意，在 Windows 上，它会提示有关正在使用的网络：

![socket.io 简介](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_03_005.jpg)

只需单击**允许访问**，然后单击**确定**。

现在当我们访问`http://localhost/client.html`时，我们应该看到以下内容：

![socket.io 简介](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-prog-bp/img/image_03_006.jpg)

但是，我们需要通过添加用户名和电子邮件来改进联系表单，以便支持人员在没有支持人员回复用户的情况下通过电子邮件回复他。

我们的表单现在如下所示：

```php
<form class="message-form" id="chatform"> 
         <input type="text" name="firstname" size="25" placeholder="Your Name"> 
         <input type="text" name="email" size="25" placeholder="Email"> 

         <input type="text" name="message" size="40" placeholder="Type your message here" /> 
         <button>Send message</button> 
   </form> 

```

由于我们添加了这些细节，我们需要将它们存储在我们的数据库中。我们可以通过将所有数据转发到另一个 PHP 脚本来执行发送。在 JavaScript 中，代码将向处理程序添加一种从表单发送到`sendsupportmessage.php`的方式。

以下是使用 jQuery 编写的 JavaScript 代码的样子：

```php
<script> 
$(document).ready(function() { 
   $('submit').on('click', function() { 
     $.post('sendsupportmessage.php', $("#chatform").serialize()) 
       .done(function(data) { 
         alert('Your message has been sent'); 
      }); 
   }); 
}); 
</script> 

```

在将接收消息的脚本`sendsupportmessage.php`中，我们需要解析信息并创建一封发送到支持电子邮件`contact@yoursite.com`的电子邮件；请参考以下示例：

```php
<?php 
  if( !empty($_POST['message'])) { 
    $message = htmlentities($_POST['message']); 
  } 

  if( !empty($_POST['email'])) { 
    $email = htmlentities($_POST['email']); 
  } 

  if( !empty($_POST['firstname']) ) { 
    $firstname = htmlentities($_POST['firstname']); 
  }  

  $emailmessage = 'A support message from ' . $firstname . '; 
  $emailmessage .=  ' with email address: ' . $email . '; 
  $emailmessage .= ' has been received. The message is '. $message; 

   mail('contact@yoursite.com', 'Support message', $emailmessage);  

  echo "success!"; 
?> 

```

该脚本只是检查提交的值是否不为空。根据经验，使用`!empty()`而不是使用`isset()`函数检查设置的值更好，因为 PHP 可能会将空字符串（''）评估为已设置：

```php
$foo = ''; 
if(isset($foo)) { print 'But no its empty'; } 
else { print 'PHP7 rocks!'; } 

```

现在我们需要向用户显示，因为我们使用 AJAX 将消息发送到服务器，并更新 AJAX 框。在 JavaScript 代码中，我们应该将`.done()`回调代码更改为以下内容：

```php
.done(function(data) { 
   if(data === 'succcess!') { 
     var successHtml = '<li>Your message was sent</li>'; 
     $('.message-list').append(successHtml); 

   } 
      } 

```

太棒了！请注意，我们更改了警报框的调用，而是将消息`您的消息已发送`附加回消息列表中。我们的支持表单现在发送了消息的发送者，并且我们的支持团队可以在他们的电子邮件中收到消息。

# 总结

在本章中，您学到了很多。总之，我们建立了一个简单的管理系统来管理我们的营销人员。此外，我们还为新闻通讯的成员创建了一个登录方式，这将引导用户到主页。

然后我们回顾了如何使用简单的模板系统发送电子邮件，这允许用户添加自己的菜单和内容到布局中。我们还能够使用 Facebook PHP SDK 和其认证过程添加 Facebook 社交登录。

在本章的后半部分，我们建立了一个简单的聊天系统，它将立即发送电子邮件到我们网站的支持电子邮件地址。我们查看了 Ratchet，这是一个 PHP 库，可以帮助我们在 PHP 中处理实时消息，并使用 AJAX 异步发送数据到另一个将发送电子邮件到支持电子邮件的脚本。

我们现在已经创建了一个令人印象深刻的新闻通讯应用程序，它不仅具有社交登录功能和支持聊天框，还允许其他新闻通讯营销人员通过网站管理其内容。
