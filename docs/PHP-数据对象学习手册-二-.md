# PHP 数据对象学习手册（二）

> 原文：[`zh.annas-archive.org/md5/33ff31751d56930c46ef1daf9ca0ebcb`](https://zh.annas-archive.org/md5/33ff31751d56930c46ef1daf9ca0ebcb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：准备好的语句

在前几章中，我们已经了解了 PDO 的基础知识，您可能已经注意到它的大部分功能类似于用于连接数据库的传统扩展。唯一的新功能是异常，但即使这一点也可以类似于传统的错误处理。

在本章中，我们将看到 PHP 中 PDO 之前不存在的一个新概念：准备好的语句。我们将看到它们如何进一步简化我们的代码，甚至提高性能。我们还将看看 PDO 如何以数据库无关的方式处理 BLOBs。

关于我们的图书馆管理应用程序，我们将重写前一章中添加的编辑/更新功能，以便支持准备好的语句，并添加对书籍封面图片的支持，我们将保存在数据库中。

# 准备好的语句

**准备好的语句**是针对数据库执行一个或多个 SQL 查询的模板。准备好的语句的理念是，对于使用相同语法但不同值的查询，预处理语法一次，然后使用不同参数多次执行会更快。考虑以下任务。我们必须将几位新作者的姓名插入到我们的数据库中。当然，我们可以使用命令行客户端或我们最近创建的`add author`页面，但我们决定使用一个 PHP 脚本。

假设要添加的作者保存在一个 PHP 数组中：

```php
$authors = array(
array(
'firstName' => 'Alexander',
'lastName' => 'Dumas',
'bio' => 'Alexandre Dumas was a French writer, best known for his
numerous historical novels of high adventure which have
made him one of the most widely read French authors in
the world.'),
array(
'firstName' => 'Ivan',
'lastName' => 'Franko',
'bio' => 'Ivan Franko was a Ukrainian poet, writer, social and
literary critic, and journalist. In addition to his own
literary work, he translated the works of William
Shakespeare, Lord Byron, Dante, Victor Hugo, Goethe and
Schiller into the Ukrainian language.'));

```

这是一个二维数组，我们将使用`foreach`循环来迭代，以便将两位作者的详细信息插入到数据库中。

```php
foreach($authors as $author)
{
$conn->query(
'INSERT INTO authors(firstName, lastName, bio) VALUES(' .
$conn->quote($author['firstName']) .
',' . $conn->quote($author['lastName']) .
',' . $conn->quote($author['bio'])')' .
);
}

```

正如您所看到的，我们在每次迭代中为每个作者创建一个 SQL 语句，并引用所有参数。

使用准备好的语句，我们可以只构建一次查询，然后通过传递不同的值任意次数执行它。我们的代码将如下所示：

```php
$stmt = $conn->prepare('INSERT INTO authors(firstName, lastName, bio)
VALUES(?, ?, ?)');
foreach($authors as $author)
{
$stmt->execute(
array($author['firstName'], $author['lastName'],
$author['bio']));
}

```

从上面的代码片段中，您可以看到准备好的语句首先通过调用`PDO::prepare()`方法*准备*。该方法接受一个包含 SQL 命令的字符串，其中变化的值被问号字符替换。调用返回一个`PDOStatement`类的对象。然后在循环中，我们调用语句的`execute()`方法，而不是`PDO::query()`方法。

`PDOStatement::execute()`方法接受一个值数组，这些值将被插入到 SQL 查询中，取代问号。该数组中的元素数量和顺序必须与传递给`PDO::prepare()`的查询模板中问号的数量和顺序相同。

您一定注意到我们在代码中没有使用`PDO::quote()`——PDO 会正确引用传入的值。

## 位置和命名占位符

前面的例子使用问号来指定准备好的语句中数值的位置。这就是为什么这些问号被称为**位置占位符**。当使用它们时，您必须注意传递给`PDOStatement::execute()`方法的数组中元素的正确顺序。虽然它们写起来很快，但当您更改查询列时，它们可能成为难以跟踪错误的源泉。为了保护自己免受这种影响，您可以使用所谓的**命名占位符**，它们由冒号前面的描述性名称组成，而不是问号。

使用命名占位符，我们可以以以下方式重写代码来插入这两位作者：

```php
$stmt = $conn->prepare(
'INSERT INTO authors(firstName, lastName, bio) ' .
'VALUES(:first, :last, :bio)');
foreach($authors as $author)
{
$stmt->execute(
array(
':first' => $author['firstName'],
':last' => $author['lastName'],
':bio' => $author['bio'])
);
}

```

正如您所看到的，我们用命名占位符替换了三个问号，然后在调用`PDOStatement::execute()`时，我们提供了一个键值对数组，其中键是相应的命名占位符，值是我们要插入数据库的数据。

使用命名占位符时，数组中元素的顺序并不重要，只有关联才重要。例如，我们可以将循环重写如下：

```php
foreach($authors as $author)
{
$stmt->execute(
array(
':bio' => $author['bio'],
':last' => $author['lastName'],
':first' => $author['firstName'])
);
}

```

然而，对于位置占位符，只要我们确保其元素的顺序与占位符的顺序匹配，就可以将`$author`数组的值传递给`PDOStatement::execute()`方法：

```php
$stmt = $conn->prepare(
'INSERT INTO authors(firstName, lastName, bio) VALUES(?, ?, ?)');
foreach($authors as $author)
{
$stmt->execute(array_values($author));
}

```

请注意我们如何使用`array_values()`函数来摆脱字符串键并将关联数组转换为列表。

如果我们向`PDOStatement::execute()`提供的值数组与查询中的占位符数量不匹配，或者我们向使用位置占位符的语句传递了一个关联数组（或向使用命名占位符的语句传递了一个列表），这将被视为错误，并且将抛出异常（前提是之前在调用`PDO::setAttribute()`方法中启用了异常）。

关于占位符的使用有一件重要的事情需要注意。它们不能作为您传递给数据库的值的一部分。这最好通过一个无效使用示例来演示：

```php
$stmt = $conn->prepare("SELECT * FROM authors WHERE lastName
LIKE '%?%'");
$stmt->execute(array($_GET['name']));

```

这必须重写为：

```php
$stmt = $conn->prepare("SELECT * FROM authors WHERE lastName
LIKE ?");
$stmt->execute(array('%' . $_GET['name'] . '%'));

```

这里的想法是，不要将占位符放在 SQL 模板中的字符串中——这必须在调用`PDOStatement::execute()`方法中完成。

## 准备语句和绑定值

上面的示例使用了所谓的**未绑定语句**。这意味着我们在传递给`PDOStatement::execute()`方法的数组中提供了查询的值。PDO 还支持**绑定语句**，其中您可以将立即值或变量显式绑定到命名或位置占位符。

要将立即值绑定到语句，使用`PDOStatement::bindValue()`方法。此方法接受占位符标识符和一个值。占位符标识符是查询中位置占位符的问号的基于 1 的索引，或命名占位符的名称。例如，我们可以将使用位置占位符的示例重写为以下方式使用绑定值：

```php
$stmt = $conn->prepare(
'INSERT INTO authors(firstName, lastName, bio) VALUES(?, ?, ?)');
foreach($authors as $author)
{
$stmt->bindValue(1, $author['firstName']);
$stmt->bindValue(2, $author['lastName']);
$stmt->bindValue(3, $author['bio']);
$stmt->execute();
}

```

如果您喜欢使用命名占位符，可以编写：

```php
$stmt = $conn->prepare(
'INSERT INTO authors(firstName, lastName, bio) ' .
'VALUES(:last, :first, :bio)');
foreach($authors as $author)
{
$stmt->bindValue(':first', $author['firstName']);
$stmt->bindValue(':last', $author['lastName']);
$stmt->bindValue(':bio', $author['bio']);
$stmt->execute();
}

```

如您所见，在这两种情况下，我们在调用`PDOStatement::execute()`时不提供任何内容。同样，与未绑定语句一样，如果您没有为每个占位符绑定值，调用`PDOStatement::execute()`将失败，导致异常。

PDO 也可以将结果集列绑定到 PHP 变量以用于 SELECT 查询。这些变量将在每次调用`PDOStatement::fetch()`时被相应列的值修改。这是在第二章中讨论的将结果集行作为数组或对象获取的替代方法。考虑以下示例：

```php
$stmt = $conn->prepare('SELECT firstName, lastName FROM authors');
$stmt->execute();
$stmt->bindColumn(1, $first);
$stmt->bindColumn(2, $last);
while($stmt->fetch(PDO::FETCH_BOUND))
{
echo "$last, $first <br>";
}

```

这将呈现表中的所有作者。变量在调用`PDOStatement::bindColumn()`方法时绑定，该方法期望第一个参数是结果集中的列的基于 1 的索引或从数据库返回的列名，第二个参数是要更新的变量。

请注意，当使用绑定列时，应使用`PDO::FETCH_BOUND`模式调用`PDOStatement::fetch()`方法，或者应该在调用`PDOStatement::setFetchMode(PDO::FETCH_BOUND)`之前进行预设。此外，必须在调用`PDOStatement::execute()`方法之后调用`PDOStatement::bindColumn()`方法，以便 PDO 知道结果集中有多少列。

现在让我们回到我们的图书馆应用程序，并增强它以使用一些预处理语句。由于仅依赖用户提供的值的页面是*添加/编辑书籍*和*添加/编辑作者*，我们将重写两个相应的脚本，`editBook.php`和`editAuthor.php`。

当然，我们只会重写更新数据库的代码部分。对于`editBook.php`，这些是第 65 到 102 行。我将在这里为您方便起见呈现这些行：

```php
if(@$book['id']) {
$sql = "UPDATE books SET title=" . $conn->quote($_POST['title']) .
', author=' . $conn->quote($_POST['author']) .
', isbn=' . $conn->quote($_POST['isbn']) .
', publisher=' . $conn->quote($_POST['publisher']) .
', year=' . $conn->quote($_POST['year']) .
', summary=' . $conn->quote($_POST['summary']) .
" WHERE id=$book[id]";
}
else {
$sql = "INSERT INTO books(title, author, isbn, publisher, year,
summary) VALUES(" . $conn->quote($_POST['title']) .
', ' . $conn->quote($_POST['author']) .
', ' . $conn->quote($_POST['isbn']) .
', ' . $conn->quote($_POST['publisher']) .
', ' . $conn->quote($_POST['year']) .
', ' . $conn->quote($_POST['summary']) .
')';
}
// Now we are updating the DB.
// We wrap this into a try/catch block
// as an exception can get thrown if
// the ISBN is already in the table.
try
{
$conn->query($sql);
// If we are here, then there is no error.
// We can return back to books listing
header("Location: books.php");
exit;
}
catch(PDOException $e)
{
$warnings[] = 'Duplicate ISBN entered. Please correct';
}

```

正如我们所看到的，构造查询的部分非常长。使用预处理语句，可以将此代码片段重写如下：

```php
if(@$book['id']) {
$sql = "UPDATE books SET title=?, author=?, isbn=?, publisher=?
year=?, summary=? WHERE id=$book[id]";
}
else {
$sql = "INSERT INTO books(title, author, isbn, publisher, year,
summary) VALUES(?, ?, ?, ?, ?, ?)";
}
$stmt = $conn->prepare($sql);
// Now we are updating the DB.
// We wrap this into a try/catch block
// as an exception can get thrown if
// the ISBN is already in the table.
try
{
$stmt->execute(array($_POST['title'], $_POST['author'],
$_POST['isbn'], $_POST['publisher'], $_POST['year'],
$_POST['summary']));
// If we are here, then there is no error.
// We can return back to books listing.
header("Location: books.php");
exit;
}
catch(PDOException $e)
{
$warnings[] = 'Duplicate ISBN entered. Please correct';
}

```

我们遵循相同的逻辑 - 如果我们正在编辑现有书籍，我们构建一个`UPDATE`查询。如果我们要添加新书，那么我们必须使用`INSERT`查询。`$sql`变量将保存适当的语句模板。在这两种情况下，语句都有六个位置占位符，我故意将书籍 ID 硬编码到`UPDATE`查询中，以便我们可以创建并执行语句，而不管所需的操作是什么。

在我们实例化语句之后，我们将其`execute()`方法的调用包装在*try…catch*块中，因为如果 ISBN 已经存在于数据库中，可能会抛出异常。在语句成功执行后，我们将浏览器重定向到书籍列表页面。如果调用失败，我们会用一个提示通知用户 ISBN 不正确（或者书籍已经存在于数据库中）。

您可以看到我们的代码现在要短得多。此外，我们不需要引用值，因为准备好的语句已经为我们做了这个。现在您可以稍微玩弄一下，并在`common.inc.php`中将数据库更改为 MySQL 和 SQLite，以查看准备好的语句是否适用于它们两个。您可能还想重写此代码，以使用命名占位符而不是位置占位符。如果这样做，请记住在传递给`PDOStatement::execute()`方法的数组中提供占位符名称。

现在让我们看看`editAuthor.php`中的相应代码块（第 42 至 59 行）：

```php
if(@$author['id']) {
$sql = "UPDATE authors SET firstName=" .
$conn->quote($_POST['firstName']) .
', lastName=' . $conn->quote($_POST['lastName']) .
', bio=' . $conn->quote($_POST['bio']) .
" WHERE id=$author[id]";
}
else {
$sql = "INSERT INTO authors(firstName, lastName, bio) VALUES(" .
$conn->quote($_POST['firstName']) .
', ' . $conn->quote($_POST['lastName']) .
', ' . $conn->quote($_POST['bio']) .
')';
}
$conn->query($sql);
header("Location: authors.php");
exit;

```

由于我们不希望在这里出现异常，所以代码更短。现在让我们重写它以使用准备好的语句：

```php
if(@$author['id']) {
$sql = "UPDATE authors SET firstName=?, lastName=?, bio=?
WHERE id=$author[id]";
}
else {
$sql = "INSERT INTO authors(firstName, lastName, bio)
VALUES(?, ?, ?)";
}
$stmt = $conn->prepare($sql);
$stmt->execute(array($_POST['firstName'], $_POST['lastName'],
$_POST['bio']));
header("Location: authors.php");
exit;

```

再次取决于所需的操作，我们创建 SQL 模板并将其分配给`$sql`变量。然后我们实例化`PDOStatement`对象，并使用作者的详细信息调用其`execute`方法。由于我们的查询不应该失败（除非出现意外的数据库故障），我们不希望在这里出现异常，并重定向到作者列表页面。

确保您使用 MySQL 和 SQLite 测试此代码。

# 使用 BLOBs

现在让我们扩展我们的应用程序，以便我们可以上传书籍的封面图片并显示它们。与传统的数据库访问一样，我们将在书籍表中使用**BLOB 字段**，以及一个**varchar 字段**来存储图像的 MIME 类型，我们需要将其与图像数据一起提供给浏览器。此外，我们还需要另一个脚本，它将从表中获取图像数据并将其传递给浏览器。（我们将从`<img>`标签中引用此脚本。）

传统上，我们不会在对`mysql_query()`或`sqlite_query()`的调用中插入 BLOB 列 - 我们只需确保它们被正确引用。但是，使用 PDO，情况就不同了。PDO 通过流和准备好的语句处理 BLOB 列。

让我们看看以下示例：

```php
$blob = fopen('/path/to/file.jpg', 'rb');
$stmt = $conn->prepare("INSERT INTO images(data) VALUES(?)");
$stmt->bindParam(1, $blob, PDO::PARAM_LOB);
$stmt->execute();

```

正如您所看到的，我们使用`fopen()`函数以二进制模式打开要插入的文件（这样我们就不会在不同平台上遇到换行符的问题），然后在调用`PDOStatement::bindParam()`方法时将文件句柄绑定到语句，并指定`PDO::PARAM_LOB`标志（以便 PDO 了解我们绑定的是文件句柄而不是立即值）。

在对`PDOStatement::execute()`方法的调用中，PDO 将从文件中读取数据并将其传递给数据库。

### 注意

如果您想知道为什么 PDO 以这种方式工作，简短的解释是，如果您的 BLOB 非常大，查询可能会失败。通常数据库服务器有一个限制通信数据包大小的设置。（您可以将其与`post_max_size`PHP 设置进行比较）。如果您在 SQL `INSERT`或`UPDATE`语句中传递相对较大的字符串，它可能会超过数据包大小，导致查询失败。使用流，PDO 确保数据以较小的数据包发送，以便查询成功执行。

BLOBs 也应该用流来读取。因此，要检索上面示例中插入的 BLOB 列，可以使用以下代码：

```php
$id = (int)$_GET['id'];
$stmt = $db->prepare("SELECT data FROM images WHERE id=$id");
$stmt->execute();
$stmt->bindColumn(1, $blob, PDO::PARAM_LOB);
$stmt->fetch(PDO::FETCH_BOUND);
$data = stream_get_contents($blob);

```

在这种情况下，`$blob`变量将是一个可以使用流处理函数读取的流资源。在这里，我们使用了`stream_get_contents()`函数将所有数据读入`$data`变量中。如果我们想直接将数据返回给浏览器（就像我们在应用程序中将要做的那样），我们可以使用`fpassthru()`函数。

截至目前（PHP 版本 5.2.3），返回的 blob 列不是流，而是列中包含的实际数据（字符串）。有关详细信息，请参阅 PHP bug＃40913 [`bugs.php.net/bug.php?id=40913`](http://bugs.php.net/bug.php?id=40913)。因此，上述代码片段中的最后一行是不需要的，`$blob`变量将保存实际数据。下面 showCover.php 文件的源代码将返回的数据视为字符串而不是 blob，因此代码可以在当前 PHP 版本中运行。

所以，让我们开始修改我们的数据库，并向其中添加新的列：

```php
mysql> alter table books add column coverMime varchar(20);
Query OK, 3 rows affected (0.02 sec)
Records: 3 Duplicates: 0 Warnings: 0
mysql> alter table books add column coverImage blob(24000);
Query OK, 3 rows affected (0.02 sec)
Records: 3 Duplicates: 0 Warnings: 0

```

您还可以在 SQLite 命令行客户端中执行这些查询，无需修改。现在，让我们修改`editBook.php`文件。我们将在现有表单中添加另一个字段。这行将允许用户上传封面图片，并增强表单验证以检查用户是否真的上传了一张图片（通过检查上传文件的 MIME 类型）。

我们还将允许用户在不重新提交封面图片文件的情况下修改书籍的详细信息。为此，我们将仅在成功上传文件时更新封面列。因此，我们的脚本逻辑将使用两个查询。第一个将更新或创建书籍记录，第二个将更新`coverMime`和`coverImage`列。

考虑到这一点，`editBook.php`文件将如下所示：

```php
<?php
/**
* This page allows adding or editing a book
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// See if we have the book ID passed in the request
$id = (int)$_REQUEST['book'];
if($id) {
// we have the ID, get the book details from the table
$q = $conn->query("SELECT * FROM books WHERE id=$id");
$book = $q->fetch(PDO::FETCH_ASSOC);
$q->closeCursor();
$q = null;
}
else {
// we are creating a new book
$book = array();
}
// Now get the list of all authors' first and last names
// we will need it to create the dropdown box for author
$authors = array();
$q = $conn->query("SELECT id, lastName, firstName FROM authors ORDER
BY lastName, firstName");
$q->setFetchMode(PDO::FETCH_ASSOC);
while($a = $q->fetch())
{
$authors[$a['id']] = "$a[lastName], $a[firstName]";
}
// Now see if the form was submitted
if($_POST['submit']) {
// Validate every field
$warnings = array();
// Title should be non-empty
if(!$_POST['title']) {
$warnings[] = 'Please enter book title';
}
// Author should be a key in the $authors array
if(!array_key_exists($_POST['author'], $authors)) {
$warnings[] = 'Please select author for the book';
}
// ISBN should be a 10-digit number
if(!preg_match('~^\d{10}$~', $_POST['isbn'])) {
$warnings[] = 'ISBN should be 10 digits';
}
// Published should be non-empty
if(!$_POST['publisher']) {
$warnings[] = 'Please enter publisher';
}
// Year should be 4 digits
if(!preg_match('~^\d{4}$~', $_POST['year'])) {
$warnings[] = 'Year should be 4 digits';
}
// Summary should be non-empty
if(!$_POST['summary']) {
$warnings[] = 'Please enter summary';
}
**// Now validate the file upload
$uploadSuccess = false;
if(is_uploaded_file($_FILES['cover']['tmp_name'])) {
// See if the file is an image
if(!preg_match('~image/.+~', $_FILES['cover']['type'])
|| filesize($_FILES['cover']['tmp_name']) > 24000) {
$warnings[] = 'Please upload an image file less than 24K
in size';
}
else {
// Set a flag that upload is successful
$uploadSuccess = true;
}
}**
// If there are no errors, we can update the database
// If there was book ID passed, update that book
if(count($warnings) == 0) {
if(@$book['id']) {
$sql = "UPDATE books SET title=?, author=?, isbn=?,
publisher=?, year=?, summary=? WHERE
id=$book[id]";
}
else {
$sql = "INSERT INTO books(title, author, isbn, publisher,
year, summary) VALUES(?, ?, ?, ?, ?, ?)";
}
$stmt = $conn->prepare($sql);
// Now we are updating the DB.
// we wrap this into a try/catch block
// as an exception can get thrown if
// the ISBN is already in the table
try
{
$stmt->execute(array($_POST['title'], $_POST['author'],
$_POST['isbn'], $_POST['publisher'], $_POST['year'],
$_POST['summary']));
// If we are here that means that no error
**// Now we can update the cover columns
// But first we have to get the ID of the newly inserted book
if(!@$book['id']) {
$book['id'] = $conn->lastInsertId();
}
// Now see if there was an successful upload and
// update cover image
if($uploadSuccess) {
$stmt = $conn->prepare("UPDATE books SET coverMime=?,
coverImage=? WHERE id=$book[id]");
$cover = fopen($_FILES['cover']['tmp_name'], 'rb');
$stmt->bindValue(1, $_FILES['cover']['type']);
$stmt->bindParam(2, $cover, PDO::PARAM_LOB);
$stmt->execute();
}**
// We can return back to books listing
header("Location: books.php");
exit;
}
catch(PDOException $e)
{
$warnings[] = 'Duplicate ISBN entered. Please correct';
}
}
}
else {
// Form was not submitted.
// populate the $_POST array with the book's details
$_POST = $book;
}
// Display the header
showHeader('Edit Book');
// If we have any warnings, display them now
if(count($warnings)) {
echo "<b>Please correct these errors:</b><br>";
foreach($warnings as $w)
{
echo "- ", htmlspecialchars($w), "<br>";
}
}
// Now display the form
?>
**<form action="editBook.php" method="post"
enctype="multipart/form-data">**
<table border="1" cellpadding="3">
<tr>
<td>Title</td>
<td>
<input type="text" name="title"
value="<?=htmlspecialchars($_POST['title'])?>">
</td>
</tr>
<tr>
<td>Author</td>
<td>
<select name="author">
<option value="">Please select...</option>
<?php foreach($authors as $id=>$author)
{ ?>
<option value="<?=$id?>"
<?= $id == $_POST['author'] ? 'selected' : ''?>>
<?=htmlspecialchars($author)?>
</option>
<?php } ?>
</select>
</td>
</tr>
<tr>
<td>ISBN</td>
<td>
<input type="text" name="isbn"
value="<?=htmlspecialchars($_POST['isbn'])?>">
</td>
</tr>
<tr>
<td>Publisher</td>
<td>
<input type="text" name="publisher"
value="<?=htmlspecialchars($_POST['publisher'])?>">
</td>
</tr>
<tr>
<td>Year</td>
<td>
<input type="text" name="year"
value="<?=htmlspecialchars($_POST['year'])?>">
</td>
</tr>
<tr>
<td>Summary</td>
<td>
<textareaname="summary"><?=htmlspecialchars($_POST['summary'])?>
</textarea>
</td>
</tr>
**<tr>
<td>Cover Image</td>
<td><input type="file" name="cover"></td>
</tr>
<?php if(@$book['coverMime'])
{ ?>
<tr>
<td>Current Cover</td>
<td><img src="showCover.php?book=<?=$book['id']?>"></td>
</tr>
<? } ?>**
<tr>
<td colspan="2" align="center">
<input type="submit" name="submit" value="Save">
</td>
</tr>
</table>
<?php if(@$book['id']) { ?>
<input type="hidden" name="book" value="<?=$book['id']?>">
<?php } ?>
</form>
<?php
// Display footer
showFooter();

```

突出显示的部分是我们添加或更改的部分。现在，我们需要验证我们的表单和上传的文件（第 60 到 73 行）。如果上传成功，`$uploadSuccess`布尔变量将设置为`true`，我们稍后将使用这个值来查看是否需要更新封面列。由于我们也允许新书进行上传，我们使用`PDO::lastInsertId()`方法值（在第 100 行）来获取新创建书籍的 ID（否则我们只使用`$books['id']`值）。如果上传失败，我们将向`$warnings`数组添加相应的警告，并让现有的错误逻辑执行其工作。

实际的封面图片更新发生在 105 到 110 行，使用了准备好的语句和流。在我们的表单中，看到我们如何在第 140 行的表单标签上添加了`multipart/form-data`属性。这是文件上传所必需的。此外，表单现在有一个新的输入字段（第 182-185 行），允许我们选择并上传文件。接下来的行将显示当前的封面图片（如果有的话）。请注意，`<img>`标签引用了一个新文件`showCover.php`，我们现在需要创建它：

```php
<?php
/**
* This script will render a book's cover image
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// See if we have the book ID passed in the request
$id = (int)$_REQUEST['book'];
$stmt = $conn->prepare("SELECT coverMime, coverImage FROM books
WHERE id=$id");
$stmt->execute();
$stmt->bindColumn(1, $mime);
$stmt->bindColumn(2, $image, PDO::PARAM_LOB);
$stmt->fetch(PDO::FETCH_BOUND);
header("Content-Type: $mime");
echo $image;

```

现在，对于一本新书，表单看起来像这样：

![使用 BLOBs](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_04_01.jpg)

如您所见，有一个新字段允许我们上传封面图片。由于新创建的书没有任何封面图片，因此没有当前的封面图片。对于有封面图片的书，页面将如下所示：

![使用 BLOBs](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_04_02.jpg)

您现在可以使用应用程序来查看表单在不上传图片的情况下的工作方式。（如果有的话，它应该保留旧图片。）您还可以看到它如何处理过大或非图片文件。（它应该在表单上方显示警告。）确保在不同数据库之间切换，以便我们是数据库无关的。

作为封面图片的最后一步，我们可以重新格式化书籍列表页面`books.php`，以便在那里也显示封面图片。我将在这里呈现新代码，并突出显示更改的部分：

```php
<?php
/**
* This page lists all the books we have
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Display the header
showHeader('Books');
// Issue the query
$q = $conn->query("SELECT authors.id AS authorId, firstName,
lastName, books.* FROM authors, books WHERE
author=authors.id ORDER BY title");
$q->setFetchMode(PDO::FETCH_ASSOC);
// now create the table
?>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Cover</td>
<td>Author and Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
<td>Edit</td>
</tr>
<?php
// Now iterate over every row and display it
while($r = $q->fetch())
{
?>
**<tr>
<td>
<?php if($r['coverMime']) { ?>
<img src="showCover.php?book=<?=$r['id']?>">
<?php }
else
{ ?>
n/a
<? } ?>
</td>
<td>
<a href="author.php?id=<?=$r['authorId']?>">
<?=htmlspecialchars("$r[firstName] $r[lastName]")?></a><br/>
<b><?=htmlspecialchars($r['title'])?></b>
</td>**
<td><?=htmlspecialchars($r['isbn'])?></td>
<td><?=htmlspecialchars($r['publisher'])?></td>
<td><?=htmlspecialchars($r['year'])?></td>
<td><?=htmlspecialchars($r['summary'])?></td>
<td>
<a href="editBook.php?book=<?=$r['id']?>">Edit</a>
</td>
</tr>
<?php
}
?>
</table>
<a href="editBook.php">Add book...</a>
<?php
// Display footer
showFooter();

```

第一个单元格将包含图片（如果有的话）。现在作者和标题都在同一个单元格中呈现，以节省表格宽度。现在图书列表应该看起来像这样：

![使用 BLOBs](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_04_03.jpg)

# 摘要

本章向我们介绍了一个新概念：准备语句。我们已经看到它们如何简化我们的查询，并进一步保护我们免受 SQL 语法错误和代码漏洞的影响。我们还看了如何使用流处理 BLOBs，以便我们不会出现查询失败的风险。我们的应用现在可以用于上传和显示数据库中书籍的封面图片。

在下一章中，我们将看到如何确定结果集中的行数，这对于对长列表进行分页是必要的。（最常见的例子是搜索引擎将结果列表分成每页 10 个结果。）此外，我们将熟悉一个新概念：可滚动的游标，它将允许我们从指定位置开始获取结果集的子集行。


# 第五章：处理行集

现实生活中的动态数据驱动的 Web 应用程序彼此非常不同，因为它们的复杂性由它们服务的目的决定。然而，几乎所有这些应用程序都具有一些共同的特征。其中之一是对长结果列表进行分页以方便使用和更快的页面加载时间。

正确的分页需要计算从数据库返回的总行数、页面大小（可配置选项）和当前页面的数量。根据这些数据，很容易计算结果集的起始偏移量，以仅显示一部分行。

在本章中，我们将研究：

+   如何检索 PDO 返回的结果集中的行数

+   如何从指定的行号开始获取结果

# 检索结果集中的行数

正如我们在第二章中已经讨论的，`PDOStatement::rowCount()`方法不会返回查询中的正确行数。（对于 MySQL 和 SQLite 都返回零。）这种行为的原因是数据库管理系统实际上直到返回查询的最后一行才知道这个数字。`mysql_num_rows()`函数（以及其他数据库的类似函数）返回行数的原因是，当您发出查询时，它会将整个结果集预加载到内存中。

虽然这种行为可能看起来很方便，但并不推荐。如果查询返回 20 行，那么脚本可以承受内存使用。但是如果查询返回数十万行呢？它们都将保留在内存中，因此在高流量站点上，服务器可能会耗尽资源。

唯一的逻辑措施（也是 PDO 可用的唯一选项）是指示数据库自己计算行数。无论查询有多复杂，都可以重写以使用 SQL 的`COUNT()`函数，仅返回满足主查询的行数。

让我们看一下我们应用程序中使用的查询。（我们只会检查返回多行的查询。）

+   在`books.php`中，我们有一个查询，它连接两个表以呈现书籍列表以及它们的作者：

```php
SELECT authors.id AS authorId, firstName, lastName, books.*
FROM authors, books WHERE author=authors.id ORDER BY title;

```

要获取此查询返回的行数，我们应该将其重写为以下内容：

```php
SELECT COUNT(*) FROM authors, books WHERE author=authors.id;

```

请注意，这里不需要`ORDER BY`子句，因为顺序对行数并不重要。

+   在`authors.php`中，我们只是按照他们的姓和名的顺序选择所有作者：

```php
SELECT * FROM authors ORDER BY lastName, firstName;

```

这简单地重写为以下内容：

```php
SELECT COUNT(*) FROM authors;

```

+   另一个返回多行的查询在`author.php`中——它检索特定作者撰写的所有书籍：

```php
SELECT * FROM books WHERE author=$id ORDER BY title;

```

这翻译为以下内容：

```php
SELECT COUNT(*) FROM books WHERE author=$id;

```

正如您所看到的，我们以类似的方式重写了所有这些查询——通过用`COUNT(*)`替换列的列表并修剪`ORDER BY`子句。有了这个想法，我们可以创建一个函数，它将接受一个包含要执行的 SQL 的字符串，并返回查询将返回的行数。这个函数将必须执行这些简单的转换：

+   在传递的字符串中，用`COUNT(*)`替换`SELECT`和`FROM`之间的所有内容。

+   删除`ORDER BY`及其后的所有文本。

实现这种转换的最佳方法是使用正则表达式。与前几章一样，我们将使用 PCRE 扩展。我们将把该函数放入`common.inc.php`中，因为我们将从各个地方调用它：

```php
/**
* This function will return the number of rows a query will return
* @param string $sql the SQL query
* @return int the number of rows the query specified will return
* @throws PDOException if the query cannot be executed
*/
function getRowCount($sql)
{
global $conn;
$sql = trim($sql);
$sql = preg_replace('~^SELECT\s.*\sFROM~s', 'SELECT COUNT(*) FROM',
$sql);
$sql = preg_replace('~ORDER\s+BY.*?$~sD', '', $sql);
$stmt = $conn->query($sql);
$r = $stmt->fetchColumn(0);
$stmt->closeCursor();
return $r;
}

```

让我们运行一下这个函数，看看它做了什么：

1.  它将 PDO 连接对象（`$conn`）导入到本地函数范围内。

1.  它修剪了 SQL 查询开头和结尾的可能空格。

1.  两次对`preg_replace()`的调用完成了转换查询的主要任务。

注意我们如何使用模式修饰符——*s*修饰符指示 PCRE 用点匹配换行符，*D*修饰符强制$匹配整个字符串的结尾（不仅仅是在第一个换行符之前）。我们使用这些修饰符来确保函数能够正确处理多行查询。

我们现在将修改这三个脚本，以显示它们返回的每个表中的行数。让我们从`books.php`开始：

```php
<?php
/**
* This page lists all the books we have
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Display the header
showHeader('Books');
**// Get the count of books and issue the query
$sql = "SELECT authors.id AS authorId, firstName, lastName, books.*
FROM authors, books WHERE author=authors.id ORDER BY title";
$totalBooks = getRowCount($sql);
$q = $conn->query($sql);**
$q->setFetchMode(PDO::FETCH_ASSOC);
// now create the table
?>
**Total books: <?=$totalBooks?>**
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Cover</td>
<td>Author and Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
<td>Edit</td>
</tr>
<?php
// Now iterate over every row and display it
while($r = $q->fetch())
{
?>
<tr>
<td>
<?php if($r['coverMime']) { ?>
<img src="showCover.php?book=<?=$r['id']?>">
<?php } else { ?>
n/a
<? } ?>
</td>
<td>
<a href="author.php?id=<?=$r['authorId']?>"><?=htmlspecialchars
("$r[firstName] $r[lastName]")?></a><br/>
<b><?=htmlspecialchars($r['title'])?></b>
</td>
<td><?=htmlspecialchars($r['isbn'])?></td>
<td><?=htmlspecialchars($r['publisher'])?></td>
<td><?=htmlspecialchars($r['year'])?></td>
<td><?=htmlspecialchars($r['summary'])?></td>
<td>
<a href="editBook.php?book=<?=$r['id']?>">Edit</a>
</td>
</tr>
<?php
}
?>
</table>
<a href="editBook.php">Add book...</a>
<?php
// Display footer
showFooter();

```

正如你所看到的，修改非常简单——我们使用`$sql`变量来保存查询，并将其传递给`getRowCount()`函数和`$conn->query()`方法。我们还在表格上方显示一条消息，告诉我们数据库中有多少本书。

现在，如果你刷新`books.php`页面，你会看到以下内容：

![检索结果集中的行数](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_05_01.jpg)

`authors.php`的更改类似：

```php
<?php
/**
* This page lists all the authors we have
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Display the header
showHeader('Authors');
**// Get the number of authors and issue the query
$sql = "SELECT * FROM authors ORDER BY lastName, firstName";
$totalAuthors = getRowCount($sql);**
$q = $conn->query($sql);
// now create the table
?>
**Total authors: <?=$totalAuthors?>**
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>First Name</td>
<td>Last Name</td>
<td>Bio</td>
<td>Edit</td>
</tr>
<?php
// Now iterate over every row and display it
while($r = $q->fetch(PDO::FETCH_ASSOC))
{
?>
<tr>
<td><?=htmlspecialchars($r['firstName'])?></td>
<td><?=htmlspecialchars($r['lastName'])?></td>
<td><?=htmlspecialchars($r['bio'])?></td>
<td>
<a href="editAuthor.php?author=<?=$r['id']?>">Edit</a>
</td>
</tr>
<?php
}
?>
</table>
<a href="editAuthor.php">Add Author...</a>
<?php
// Display footer
showFooter();

```

`authors.php`现在应该显示以下内容：

![检索结果集中的行数](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_05_02.jpg)

最后，`author.php`将如下所示：

```php
<?php
/**
* This page shows an author's profile
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Get the author
$id = (int)$_REQUEST['id'];
$q = $conn->query("SELECT * FROM authors WHERE id=$id");
$author = $q->fetch(PDO::FETCH_ASSOC);
$q->closeCursor();
$q = null;
// Now see if the author is valid - if it's not,
// we have an invalid ID
if(!$author) {
showHeader('Error');
echo "Invalid Author ID supplied";
showFooter();
exit;
}
// Display the header - we have no error
showHeader("Author: $author[firstName] $author[lastName]");
**// Now get the number and fetch all the books
$sql = "SELECT * FROM books WHERE author=$id ORDER BY title";
$totalBooks = getRowCount($sql);
$q = $conn->query($sql);
$q->setFetchMode(PDO::FETCH_ASSOC);**
// now display everything
?>
<h2>Author</h2>
<table width="60%" border="1" cellpadding="3">
<tr>
<td><b>First Name</b></td>
<td><?=htmlspecialchars($author['firstName'])?></td>
</tr>
<tr>
<td><b>Last Name</b></td>
<td><?=htmlspecialchars($author['lastName'])?></td>
</tr>
<tr>
<td><b>Bio</b></td>
<td><?=htmlspecialchars($author['bio'])?></td>
</tr>
**<tr>
<td><b>Total books</td>
<td><?=$totalBooks?></td>
</tr>**
</table>
<a href="editAuthor.php?author=<?=$author['id']?>">Edit author...</a>
<h2>Books</h2>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
</tr>
<?php
// Now iterate over every book and display it
while($r = $q->fetch()) {
?>
<tr>
<td><?=htmlspecialchars($r['title'])?></td>
<td><?=htmlspecialchars($r['isbn'])?></td>
<td><?=htmlspecialchars($r['publisher'])?></td>
<td><?=htmlspecialchars($r['year'])?></td>
<td><?=htmlspecialchars($r['summary'])?></td>
</tr>
<?php
}
?>
</table>
<?php
// Display footer
showFooter();

```

输出应该如下所示。（我把页面向下滚动了一点以节省空间）：

![检索结果集中的行数](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_05_03.jpg)

你应该在`common.inc.php`中在 MySQL 和 SQLite 之间切换，以确保两个数据库都能工作。

### 注意

这种方法可能适用于许多情况，但并不适用于所有查询。一个这样的例子是使用`GROUP BY`子句的查询。如果你用`getRowCount()`函数重写这样的查询，你将得到不正确的结果，因为分组将被应用，查询将返回多行。（行数将等于你正在分组的列中不同值的数量。）

# 限制返回的行数

现在，我们知道如何计算结果集中的行数，让我们看看如何只获取前 N 行。这里我们有两个选项：

+   我们可以在 SQL 查询中使用特定于数据库的功能。

+   我们可以自己处理结果集，并在获取所需数量的行后停止。

## 使用特定于数据库的 SQL

如果你主要使用 MySQL，那么你会熟悉`LIMIT x,y`子句。例如，如果我们想按姓氏排序获取前五位作者，可以发出以下查询：

```php
SELECT * FROM authors ORDER BY lastName LIMIT 0, 5;

```

同样的事情也可以用以下查询完成：

```php
SELECT * FROM authors ORDER BY lastName LIMIT 5 OFFSET 0;

```

第一个查询适用于 MySQL 和 SQLite，而第二个查询也适用于 PostgreSQL。然而，像 Oracle 或 MS SQL Server 这样的数据库不使用这样的语法，所以这些查询对它们来说将失败。

## 仅处理前 N 行

正如你所看到的，特定于数据库的 SQL 不允许我们以数据库无关的方式解决执行分页的任务。然而，我们可以像对待所有行一样发出查询，而不使用`LIMIT....OFFSET`子句。在获取每一行后，我们可以增加计数器变量，这样当我们处理了所需数量的行时，我们就可以中断循环。以下代码片段可以实现这一目的：

```php
$q = $conn->query("SELECT * FROM authors ORDER BY lastName,
firstName");
$q->setFetchMode(PDO::FETCH_ASSOC);
$count = 1; **while(($r = $q->fetch()) && $count <= 5)**
{
echo $r['lastName'], '<br>';
$count++;
} **$q->closeCursor();
$q = null;**

```

注意循环条件——它检查计数器变量是否小于或等于 5。（当然，你可以在那里放任何数字），以及它验证是否还有行要获取，因为重要的是如果没有更多行要获取，我们就中断循环。（例如，如果表只有 3 行，我们想显示其中的 5 行，我们应该在最后一行后中断，而不是在计数器达到 5 后中断。）请注意，使用特定于数据库的 SQL 将为我们处理这样的情况。

另一个重要的事情是调用`PDOStatement::closeCursor()`（如前一个代码片段中倒数第二行）。有必要告诉数据库我们不需要更多的行。如果我们不这样做，那么在同一个 PDO 对象上发出的后续查询将引发异常，因为数据库管理系统无法在仍在发送上一个查询的行时处理新查询。这就是为什么我们在`author.php`中必须调用这个方法。

### 注意

目前（对于 PHP 版本 5.2.1），可能需要将语句对象取消分配为 null（如`author.php`，第 17 行）。另一方面，至少在 2007 年 4 月 1 日左右发布的一个 CVS 快照根本不需要关闭游标。但是，在完成游标后调用`PDOStatement::closeCursor()`仍然是一个好习惯。

## 从任意偏移开始

现在我们知道如何处理指定数量的行，我们可以使用相同的技术来跳过一定数量的行。假设我们想显示第 6 到第 10 位作者（就像我们在每页允许每页 5 位作者时显示第 2 页）：

```php
$q = $conn->query("SELECT * FROM authors ORDER BY lastName,
firstName");
$q->setFetchMode(PDO::FETCH_ASSOC);
$count = 1;
while(($r = $q->fetch()) && $count <= 5)
{
$count++;
}
$count = 1;
while(($r = $q->fetch()) && $count <= 5)
{
echo $r['lastName'], '<br>';
$count++;
}
$q->closeCursor();
$q = null;

```

在这里，第一个循环用于跳过必要的起始行，第二个循环显示请求的行的子集。

### 注意

这种方法对小表可能效果很好，但性能不佳。您应该始终使用特定于数据库的 SQL 来返回结果行的子集。如果您需要数据库独立性，应该检查底层数据库软件并发出特定于数据库的查询。原因是数据库可以对查询执行某些优化，使用更少的内存，从而在服务器和客户端之间交换的数据量更少。

不幸的是，PDO 没有提供数据库独立的方法来有效地获取结果行的子集，因为 PDO 是连接抽象，而不是数据库抽象工具。如果您需要编写可移植的代码，应该探索 MDB2 等工具。

这种方法可能比使用`PDOStatement::fetchAll()`方法更复杂。事实上，我们可以将上一个代码重写如下：

```php
$stmt = $conn->query("SELECT * FROM authors ORDER BY lastName,
firstName");
$page = $stmt->fetchAll(PDO::FETCH_ASSOC);
$page = array_slice($page, 5, 5);
foreach($page as $r)
{
echo $r['lastName'], '<br>';
}

```

尽管这段代码要短得多，但它有一个主要缺点：它指示 PDO 返回表中的所有行，然后取其中的一部分。使用我们的方法，不必要的行将被丢弃，并且循环指示数据库在返回足够的行后停止发送行。但是，在这两种情况下，数据库都必须向我们发送当前页面之前的行。

# 总结

在本章中，我们已经看到如何处理无缓冲查询并获取结果集的行数。我们还看了一个应用程序，其中无法避免使用特定于数据库的 SQL，因为这将需要一个可能不合适的解决方法。但是，这一章对于开发使用数据库的复杂 Web 应用程序的人应该是有帮助的。

在下一章中，我们将讨论 PDO 的高级功能，包括持久连接和其他特定于驱动程序的选项。我们还将讨论事务并检查`PDO`和`PDOStatement`类的更多方法。


# 第六章：PDO 的高级用法

现在我们已经熟悉了 PDO 的基本特性，并用它们来构建了数据驱动的 Web 应用程序，让我们来看一些高级功能。在这一章中，我们将看到如何获取和设置连接属性（比如列名、大小写转换以及底层 PDO 驱动的名称），以及通过指定连接配置文件名或在`php.ini`文件中的选项来连接数据库。我们还将讨论事务。

我们将修改我们的图书馆应用程序，以在每个页面的页脚显示数据库驱动程序的名称。除了这个简单的改变，我们还将扩展应用程序，以跟踪我们拥有的单本书的副本数量，并跟踪那些借阅了书的人。我们将使用事务来实现这个功能。

# 设置和获取连接属性

我们在第三章中简要介绍了设置连接属性，当我们看到如何使用异常作为错误报告的手段时。连接属性允许我们控制连接的某些方面，以及查询诸如驱动程序名称和版本之类的东西。

+   一种方法是在 PDO 构造函数中指定属性名称/值对的数组。

+   另一种方法是调用`PDO::setAttribute()`方法，它接受两个参数：

+   属性的名称

+   属性的值

在 PDO 中，属性及其值被定义为`PDO`类中的常量，就像在`common.inc.php`文件中的以下调用一样：

```php
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

```

它包括两个这样的常量——`PDO::ATTR_ERRMODE`和`PDO::ERRMODE_EXCEPTION`。

要获取属性的值，有`PDO::getAttribute()`方法。它接受一个参数，属性名称，并返回属性的值。例如，下面的代码将打印`Exception:`。

```php
if($conn->getAttribute(PDO::ATTR_ERRMODE) == PDO::ERRMODE_EXCEPTION) {
echo 'Exception';
}

```

现在，让我们看看 PDO 中有哪些连接属性。

+   `PDO::ATTR_CASE`。这个属性控制了`PDOStatement::fetch()`方法返回的列名的大小写。如果获取模式是`PDO::FETCH_ASSOC`或`PDO::FETCH_BOTH`（当行以包含按名称索引的列的数组返回时），这将非常有用。这个属性可以有以下三个值：`PDO::CASE_LOWER, PDO::CASE_NATURAL`和`PDO::CASE_UPPER`。根据这个值，列名将分别是小写、不改变、或大写，就像下面的代码片段一样：

```php
$conn->setAttribute(PDO::ATTR_CASE, PDO::CASE_UPPER);
$stmt = $conn->query("SELECT * FROM authors LIMIT 1");
$r = $stmt->fetch(PDO::FETCH_ASSOC);
$stmt->closeCursor();
var_dump($r);

```

将会打印：

```php
array(4)
{
["ID"]=>
string(1) "1"
["FIRSTNAME"]=>
string(4) "Marc"
["LASTNAME"]=>
string(7) "Delisle"
["BIO"]=>
string(54) "Marc Delisle is a member of the MySQL Developers
Guild"
}

```

默认行为是不改变列名的大小写，即`PDO::CASE_NATURAL`。

+   `PDO::ATTR_ORACLE_NULLS:` 这个属性，尽管名字是这样，但是对所有数据库都有效，不仅仅是 Oracle。它控制了`NULL`值和空字符串在 PHP 中的传递。可能的取值有`PDO::NULL_NATURAL`（表示不进行任何转换），`PDO::NULL_EMPTY_STRING`（表示空字符串将被替换为 PHP 的 null 值），以及`PDO::NULL_TO_STRING`（表示 SQL 的 NULL 值在 PHP 中被转换为空字符串）。

你可以看到这个属性是如何工作的，下面是代码：

```php
$conn->setAttribute(PDO::ATTR_ORACLE_NULLS, PDO::NULL_TO_STRING);
$stmt = $conn->query("SELECT * FROM books WHERE coverImage IS
NULL LIMIT 1");
$r = $stmt->fetch(PDO::FETCH_ASSOC);
$stmt->closeCursor();
var_dump($r);

```

将会产生：

```php
array(9)
{
["id"]=>
string(1) "2"
["author"]=>
string(1) "2"
["title"]=>
string(18) "ImageMagick Tricks"
["isbn"]=>
string(10) "1904811868"
["publisher"]=>
string(20) "Packt Publishing Ltd"
["year"]=>
string(4) "2006"
["summary"]=>
string(81) "Unleash the power of ImageMagick
with this fast,friendly tutorial and tips guide"
["coverMime"]=>
string(0) ""
["coverImage"]=>
string(0) ""
}

```

正如你所看到的，高亮显示的字段被报告为字符串，而不是 NULL（如果我们没有设置`PDO::ATTR_ORACLE_NULLS`属性的话）。

+   `PDO::ATTR_ERRMODE`。这个属性设置了连接的错误报告模式。它接受三个值：

+   `PDO::ERRMODE_SILENT:` 不采取任何行动，错误代码可以通过`PDO::errorCode()`和`PDO::errorInfo()`方法（或它们在`PDOStatement`类中的等价物）获得。这是默认值。

+   `PDO::ERRMODE_WARNING:` 与以前一样，不采取任何行动，但会引发一个`E_WARNING`级别的错误。

+   `PDO::ERRMODE_EXCEPTION`将设置错误代码（与`PDO::ERRMODE_SILENT`一样），并且将抛出一个`PDOException`类的异常。

还有特定于驱动程序的属性，我们在这里不会涉及。有关更多信息，请参阅[`www.php.net/pdo`](http://www.php.net/pdo)。但是，有一个值得我们关注的特定于驱动程序的属性：`PDO::ATTR_PERSISTENT`。您可以使用它来指定 MySQL 驱动程序应该使用持久连接，这样可以获得更好的性能（您可以将其视为`mysql_pconnect()`函数的对应物）。此属性应该在 PDO 构造函数中设置，而不是通过 PDO::setAttribute()调用：

```php
$conn = new PDO($connStr, $user, $pass,
array(PDO::ATTR_PERSISTENT => true);

```

上述三个属性是读/写属性，这意味着它们可以被读取和写入。还有只能通过`PDO::getAttribute()`方法获得的只读属性。这些属性可能返回字符串值（而不是在 PDO 类中定义的常量）。

+   `PDO::ATTR_DRIVER_NAME:` 这将返回底层数据库驱动程序的名称：

```php
echo $conn->getAttribute(PDO::ATTR_DRIVER_NAME);

```

这将打印出 MySQL 或 SQLite，具体取决于您使用的驱动程序。

+   `PDO::ATTR_CLIENT_VERSION:` 这将返回底层数据库客户端库版本的名称。例如，对于 MySQL，这可能是类似于 5.0.37 的东西。

+   `PDO::ATTR_SERVER_VERSION:` 这将返回您正在连接的数据库服务器的版本。对于 MySQL，这可以是一个字符串，比如`"4.1.8-nt"`。

现在让我们回到我们的应用程序，并修改它以在每个页面的页脚中显示数据库驱动程序。为了实现这一点，我们将修改`common.inc.php`中的`showFooter()`函数：

```php
function showFooter()
{
global $conn;
if($conn instanceof PDO) {
$driverName = $conn->getAttribute(PDO::ATTR_DRIVER_NAME);
echo "<br/><br/>";
echo "<small>Connecting using $driverName driver</small>";
}
?>
</body>
</html>
<?php
}

```

在此函数中，我们从全局命名空间导入了`$conn`变量。如果此变量是`PDO`类的对象，那么我们将调用上面讨论的`getAttribute()`方法。我们必须进行此检查，因为在某些情况下，`$conn`变量可能未设置。例如，如果`PDO`构造函数失败并抛出异常，我们将无法调用`$conn`变量上的任何方法（这将导致致命错误——在非对象上调用成员函数是致命错误）。

由于我们应用程序中的所有页面都调用`showFooter()`方法函数，这个改变将在所有地方都可见：

![设置和获取连接属性](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_06_01.jpg)![设置和获取连接属性](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_06_02.jpg)

# MySQL 缓冲查询

如果您只使用 MySQL 数据库，那么您可能希望使用 MySQL 的 PDO 驱动程序缓冲查询模式。当连接设置为缓冲查询模式时，每个 SELECT 查询的整个结果集都会在返回到应用程序之前预先获取到内存中。这给我们带来了一个好处——我们可以使用`PDOStatement::rowCount()`方法来检查结果集包含多少行。在第二章中，我们讨论了这个方法，并展示了它对 MySQL 和 SQLite 数据库返回 0 的情况。现在，当 PDO 被指示使用缓冲查询时，这个方法将返回有意义的值。

要强制 PDO 进入 MySQL 缓冲查询模式，您必须指定`PDO::MYSQL_ATTR_USE_BUFFERED_QUERY`连接属性。考虑以下示例：

```php
$conn = new PDO($connStr, $user, $pass);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); **$conn->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, 1);**
$q = $conn->query("SELECT * FROM books");
echo $q->rowCount();

```

这将打印返回的行数。

请注意，此属性仅适用于 MySQL，并且在数据库之间不可移植。如果您的应用程序只使用 MySQL，应该使用它。此外，请记住，返回大型结果集的缓冲查询在资源方面非常昂贵，应该避免使用。如果要使用缓冲查询，请确保在发出此类昂贵的查询之前禁用它们。可以通过关闭此属性来实现：

```php
$conn->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, 0);

```

您可以通过调用查询 MySQL 缓冲查询是否当前启用

```php
$conn->getAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY);

```

我已经为每个截图切换了数据库（并且在第一个截图中，页面向下滚动到底部以节省空间）。

# 使用连接配置文件和 php.ini 设置连接

当我们讨论连接字符串（或 PDO 的数据源名称）时，我们看到连接字符串以驱动程序名称开头，后跟一个分号。PDO 还支持配置文件 - 包含连接字符串的文件。例如，我们可以在应用程序文件所在的目录中创建一个名为`pdo.dsn`的文件，并在其中放置连接字符串：

```php
mysql:host=localhost;dbname=pdo
or
sqlite:/www/hosts/localhost/pdo.db

```

或者，我们可以创建两个文件，`mysql.dsn`和`sqlite.dsn`，分别包含第一个和第二个连接字符串。

然后在 PDO 构造函数中，我们可以指定配置文件路径或 URL，而不仅仅是连接字符串：

```php
uri:./pdo.dsn

```

PDO 将读取文件并使用其中指定的连接字符串。使用此方法的优势在于，您不仅可以指定本地文件，还可以指定任何 URL，以便包含远程文件（前提是系统为诸如 HTTP 或 FTP 之类的协议注册了合适的流处理程序）。另一方面，如果文件未受到所有用户的网络访问保护，则可能会向第三方泄露安全信息，因此在使用此方法指定连接字符串时应谨慎。

还有另一种指定连接字符串的方法：在`php.ini`文件中。例如，您可以在`php.ini`文件中定义以下指令：

```php
pdo.dsn.mysql= mysql:host=localhost;dbname=pdo
pdo.dsn.sqlite=sqlite:/www/hosts/localhost/pdo.db

```

然后可以分别将'mysql'或'sqlite'字符串传递给`PDO`构造函数，而不是整个 mysql 和 sqlite 的连接字符串：

```php
$conn = new PDO('mysql', $user, $pass);
$conn = new PDO('sqlite', $user, $pass);

```

如您所见，此处的连接字符串应与`php.ini`文件中的相应选项匹配，带有`'pdo.dsn'`前缀。

# 获取可用驱动程序列表

PDO 允许您以编程方式获取所有已安装驱动程序的列表。可以调用`PDO::getAvailableDrivers()`方法返回一个包含可以使用的数据库驱动程序名称的数组。例如，此代码将打印类似以下内容的内容：

```php
var_dump(PDO::getAvailableDrivers());
array(3)
{
[0]=>
string(5) "mysql"
[1]=>
string(6) "sqlite"
[2]=>
string(7) "sqlite2"
}

```

此数组中包含的驱动程序名称是连接字符串的前缀。同时，相同的名称作为`PDO::ATTR_DRIVER_NAME`属性的值返回。

### 注意

`PDO::getAvailableDrivers()`方法返回在`php.ini`文件中注册到 PDO 系统的驱动程序的名称。您可能无法在本地机器上使用所有这些驱动程序 - 例如，如果 MySQL 服务器未运行，则返回的数组中存在 MySQL 项目并不意味着您可以连接到本地 MySQL 服务器，如果某个数据库服务器在本地机器上运行，但其驱动程序未注册到 PDO，则您将无法连接到该数据库服务器。

# 交易

PDO API 还标准化了事务处理方法。默认情况下，在成功创建 PDO 连接后，它被设置为`autocommit`模式。这意味着对于每个支持事务的数据库，每个查询都包装在一个隐式事务中。对于那些不支持事务的数据库，每个查询都会按原样执行。

通常，事务处理策略是这样的：

1.  开始交易。

1.  将与数据库相关的代码放在*try...catch*块中。

1.  与数据库相关的代码（在*try*块中）应在所有更新完成后提交更改。

1.  *catch*块应回滚事务。

当然，只有更新数据库的代码和可能破坏数据完整性的代码应该在事务中处理。交易的一个经典例子是资金转移：

1.  开始交易。

1.  如果付款人的帐户上有足够的钱：

+   从付款人的帐户中扣除金额。

+   向受益人的帐户中添加金额。

1.  提交交易。

如果在交易中间发生了任何不好的事情，数据库不会得到更新，数据完整性得到保留。此外，通过将帐户余额检查包装到交易中，我们确保并发更新不会破坏数据完整性。

PDO 只提供了三种处理事务的方法：`PDO::beginTransaction()`用于启动事务，`PDO::commit()`用于提交自从调用`PDO::beginTransaction()`以来所做的更改，`PDO::rollBack()`用于回滚自从启动事务以来的任何更改。

`PDO::beginTransaction()`方法不接受任何参数，并根据事务启动的成功与否返回一个布尔值。如果调用此方法失败，PDO 将抛出一个异常（例如，如果您已经处于事务中，PDO 会告诉您）。同样，如果没有活动事务，`PDO::rollBack()`方法将抛出一个异常，如果在调用`PDO::beginTransaction()`之前调用`PDO::commit()`方法，也会发生相同的情况。（当然，您的错误处理模式必须设置为`PDO::ERRMODE_EXCEPTION`才能抛出异常。）

还应该注意，如果您正在使用 PDO 进行任务控制，不应该使用直接查询来控制事务。我们的意思是，您不应该使用诸如`BEGIN TRANSATION，COMMIT`或`ROLLBACK`等查询来使用`PDO::query()`方法。否则，这三种方法的行为将是不一致的。此外，PDO 目前不支持保存点。

现在让我们回到我们的图书馆应用程序。为了看看事务是如何实际工作的，我们将修改它，使其能够跟踪我们有多少本特定书籍的副本，并实现一个函数来跟踪我们借出书籍的人。

这个修改将包括以下更改：

+   我们将不得不通过向书籍表添加一个新列来修改书籍表，以保留每本书的副本数量。`editBook.php`页面将需要修改以更改这个值。

+   我们将创建一个表来跟踪所有借阅者，但为了简化示例，我们不会创建一个借阅者表（就像我们为真实的图书馆应用程序所做的那样）。我们只会将借阅者的姓名与我们借给他们的书籍的书籍 ID 关联起来。

+   我们将创建一个页面，用于借出书籍。这个页面将要求借阅者的姓名，然后将记录插入到借阅者表中，并减少书籍表中的副本数量。

+   我们还需要一个页面，用于列出所有借阅者，以及另一个脚本，允许他们归还书籍。这个脚本将从借阅者表中删除一条记录，并增加书籍表中的副本数量。

我们只在同时更新两个表时使用事务（就像上面列表中的最后两点）。

在进行编码之前，我们将修改书籍表：

```php
mysql> alter table books add column copies tinyint not null default 1;
Query OK, 3 rows affected (0.50 sec)
Records: 3 Duplicates: 0 Warnings: 0

```

对于 SQLite，应该执行相同的命令。

现在，让我们稍微修改`books.php`，以显示每本书的副本数量，并提供一个链接。以下是需要更改的代码行（第 20 至 58 行）：

```php
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Cover</td>
<td>Author and Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
**<td>Copies</td>
<td>Lend</td>**
<td>Edit</td>
</tr>
<?php
// Now iterate over every row and display it
while($r = $q->fetch())
{
?>
<tr>
<td>
<?php if($r['coverMime']) { ?>
<img src="showCover.php?book=<?=$r['id']?>">
<?php } else { ?>
n/a
<? } ?>
</td>
<td>
<a href="author.php?id=<?=$r['authorId']?>"><?=htmlspecialchars
("$r[firstName] $r[lastName]")?></a><br/>
<b><?=htmlspecialchars($r['title'])?></b>
</td>
<td><?=htmlspecialchars($r['isbn'])?></td>
<td><?=htmlspecialchars($r['publisher'])?></td>
<td><?=htmlspecialchars($r['year'])?></td>
<td><?=htmlspecialchars($r['summary'])?></td>
**<td><?=$r['copies']?></td>
<td>
<a href="lendBook.php?book=<?=$r['id']?>">Lend</a>
</td>**
<td>
<a href="editBook.php?book=<?=$r['id']?>">Edit</a>
</td>
</tr>
<?php
}
?>

```

现在，对于 MySQL 和 SQLite，您应该看到一个页面，就像以下的屏幕截图一样（我们已经向下滚动并向右滚动，以便它适合页面）：

![Transactionsdriver listgetting, getAvailableDrivers() method used](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_06_03.jpg)

现在，让我们创建借阅者表。正如我们之前讨论过的，该表将包含一个 ID 字段，书籍的 ID 字段，借阅者的姓名和一个时间戳列。我们需要在这个表上有一个 ID（主键），以防止可能的数据损坏；例如，如果同一个借阅者两次借同一本书。如果我们只通过姓名和书籍 ID 跟踪借阅者，那么在该表中可能会有重复的记录，而归还一本书可能会删除该表中的多行，这将导致数据损坏：

```php
mysql> create table borrowers(
-> id int primary key not null auto_increment,
-> book int not null,
-> name varchar(40),
-> dt int);
Query OK, 0 rows affected (0.13 sec)

```

对于 SQLite，语法会有些不同：

```php
sqlite> create table borrowers(
...> id integer primary key,
...> book int not null,
...> name varchar(40),
...> dt int);

```

借出图书的页面（`lendBook.php`）可能是最困难的部分。这个页面将包括一个表单，您可以在其中输入借阅者的姓名。提交成功后，脚本将启动事务，检查图书是否至少有一本可用，向借阅者表插入一条记录并减少图书表中的副本列，提交事务，并重定向到`books.php`页面。

```php
<?php
/**
* This page allows lending a book
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// First see if the request contains the book ID
// Return back to books.php if not
$id = (int)$_REQUEST['book'];
if(!$id) {
header("Location: books.php");
exit;
}
// Now see if the form was submitted
$warnings = array();
if($_POST['submit']) {
// Require that the borrower's name is entered
if(!$_POST['name']) {
$warnings[] = 'Please enter borrower\'s name';
}
else {
// Form is OK, "lend" the book
$conn->beginTransaction();
try
{
$stmt = $conn->query("SELECT copies FROM books WHERE id=$id");
$copies = $stmt->fetchColumn();
$stmt->closeCursor();
if($copies > 0) {
// If we can lend it
$conn->query("UPDATE books SET copies=copies-1
WHEREid=$id");
$stmt = $conn->prepare("INSERT INTO borrowers(book, name, dt)
VALUES(?, ?, ?)");
$stmt->execute(array($id, $_POST['name'], time()));
}
else {
// Else show warning
$warnings[] = 'There are no more copies of this book
available';
}
$conn->commit();
}
catch(PDOException $e)
{
// Something bad happened
// Roll back and rethrow the exception
$conn->rollBack();
throw $e;
}
}
// Now, if we don't have errors,
// redirect back to books.php
if(count($warnings) == 0) {
header("Location: books.php");
exit;
}
// otherwise, the warnings will be displayed
}
// Display the header
showHeader('Lend Book');
// If we have any warnings, display them now
if(count($warnings)) {
echo "<b>Please correct these errors:</b><br>";
foreach($warnings as $w)
{
echo "- ", htmlspecialchars($w), "<br>";
}
}
// Now display the form
?>
<form action="lendBook.php" method="post">
<input type="hidden" name="book" value="<?=$id?>">
<b>Please enter borrower's name:<br></b>
<input type="text" name="name"value="<?=htmlspecialchars
($_POST['name'])?>">
<input type="submit" name="submit" value=" Lend book ">
</form>
<?php
// Display footer
showFooter();

```

现在让我们来看看代码。我们首先检查图书的 ID 是否通过 URL 或表单传递给脚本。（我们将 ID 保存在表单的隐藏字段中。）然后，如果有表单提交（按下提交按钮），我们检查姓名字段是否填写正确。如果测试成功，我们继续进行事务，在其中计算剩余的副本数量，并检查这个数字是否大于零，我们减少副本列，并使用准备好的语句将一条记录插入到`borrowers`表中。如果副本少于一本，我们向`$warnings`数组添加一条消息，以便在页面上显示警告。

如果事务中出现故障，将执行`catch`块。事务将被回滚，并且异常将再次被抛出。我们这样做是为了让我们的默认错误处理程序发挥作用。

现在，如果您将上面的代码列表保存在`lendBook.php`中，并点击图书列表页面上的一个**借出**链接，您应该会到达以下页面：

![Transactionsdriver listgetting, getAvailableDrivers() method used](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_06_04.jpg)

当然，你应该在数据库之间切换，以查看代码是否与 MySQL 和 SQLite 一起工作。

### 注意

为了增强页面，我们还应该显示图书的标题和作者，但这部分留给你。另外，如果你想知道为什么我们在表单提交后才警告用户没有更多的副本，这是因为我们只能在事务中决定这一点。如果我们在事务中检测到有副本可用，那么我们才能确保没有并发更新会改变这一点。当然，从用户的角度来看，另一个补充可能是在图书详情旁边显示一个警告。然而，事务中也需要进行检查。

现在，如果您借出一本书，您会看到图书列表页面上的**副本**列已经减少。现在，让我们创建一个页面，列出所有借阅者和借给他们的图书。让我们称之为`borrowers.php`。虽然这个页面不处理任何用户输入，但它包含一个查询，连接了三个表（借阅者、图书和作者）：

```php
<?php
/**
* This page lists all borrowed books
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Display the header
showHeader('Lended Books');
// Get all lended books count and list
$sql = "SELECT borrowers.*, books.title, authors.firstName,
authors.lastName
FROM borrowers, books, authors
WHERE borrowers.book=books.id AND books.author=authors.id
ORDER BY borrowers.dt";
$totalBooks = getRowCount($sql);
$q = $conn->query($sql);
$q->setFetchMode(PDO::FETCH_ASSOC);
// now create the table
?>
Total borrowed books: <?=$totalBooks?>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Title</td>
<td>Author</td>
<td>Borrowed by</td>
<td>Borrowed on</td>
<td>Return</td>
</tr>
<?php
// Now iterate over every row and display it
while($r = $q->fetch())
{
?>
<tr>
<td><?=htmlspecialchars($r['title'])?></td>
<td><?=htmlspecialchars("$r[firstName] $r[lastName]")?></td>
<td><?=htmlspecialchars($r['name'])?></td>
<td><?=date('d M Y', $r['dt'])?></td>
<td>
<a href="returnBook.php?borrower=<?=$r['id']?>">Return</a>
</td>
</tr>
<?php
}
?>
</table>
<?php
// Display footer
showFooter();

```

代码很容易理解；它遵循与`books.php`或`authors.php`相同的逻辑。但是，由于这个页面没有从任何地方链接过来，我们应该在网站页眉（`common.inc.php`中的`showHeader()`函数）中添加一个链接：

```php
function showHeader($title)
{
?>
<html>
<head><title><?=htmlspecialchars($title)?></title></head>
<body>
<h1><?=htmlspecialchars($title)?></h1>
<a href="books.php">Books</a>
<a href="authors.php">Authors</a>
**<a href="borrowers.php">Borrowers</a>**
<hr>
<?php
}

```

现在，如果您导航到`borrowers.php`，您应该看到类似于这个屏幕截图的东西：

![Transactionsdriver listgetting, getAvailableDrivers() method used](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_06_05.jpg)

正如我们所看到的，这个页面包含指向`returnBook.php`页面的链接，但这个页面还不存在。这个脚本将从借阅者表中删除相关记录，并增加图书表中的副本列。这个操作也将被包装在一个事务中。此外，`returnBook.php`接受借阅者表的 ID 字段（与`lendBook.php`接受图书的 ID 相反）。因此，我们还应该从借阅者表中获取图书的 ID：

```php
<?php
/**
* This page "returns" a book back to the library
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// First see if the request contains the borrowers ID
// Return back to books.php if not
$id = (int)$_REQUEST['borrower'];
if(!$id) {
header("Location: books.php");
exit;
}
// Now start the transaction
$conn->beginTransaction();
try
{
$q = $conn->query("SELECT book FROM borrowers WHERE id=$id");
$book = (int)$q->fetchColumn();
$q->closeCursor();
$conn->query("DELETE FROM borrowers WHERE id=$id");
$conn->query("UPDATE books SET copies=copies+1 WHERE id=$book");
$conn->commit();
header("Location: books.php");
}
catch(PDOException $e)
{
$conn->rollBack();
throw $e;
}

```

代码应该是相当自解释的。首先，我们检查请求是否包含借阅者的 ID，然后更新两个表。成功完成后，我们将被重定向到图书列表页面，否则，错误处理程序将显示相关消息。

现在，最后的一步：`editBook.php`页面，可以用来编辑我们拥有的书籍副本数量。我们将把这个任务留给你，但这里有一些考虑。跟踪已借出的书籍的建议方式对于实际的图书馆应用来说并不是很好。我们应该保留图书馆中总副本数的一个列，以及已借出的副本数的另一个列，而不是保留可用副本数。这样做是因为编辑可用书籍的数量可能会导致数据损坏。归还一本书将增加图书表中的副本列。如果同时有其他人在编辑可用副本数，他们可能不知道借阅者正在归还一本书，因此可能输入一个不正确的数字。

另一方面，如果有两个独立的列，那么更新总副本数将完全独立于借出和归还书籍所引起的更新。然而，在这种情况下，借书的脚本应该检查已借出的副本数是否小于总副本数。只有在满足这个条件的情况下，事务才能继续。

# 总结

在本章中，我们看了一些 PDO 提供的扩展功能，特别是事务。我们修改了应用示例，提供了依赖事务的额外功能。我们还看了事务感知代码的组织。

然而，正如你可能已经注意到的，我们在一个文件中混合了更新数据库、处理用户输入和呈现页面的代码。虽然我们试图将输入处理和呈现分开放在一个文件的不同部分（首先是数据处理，然后是页面呈现），但我们无法分开数据处理。

在下一章中，我们将看到如何分离数据模型和应用逻辑，以便数据不仅可以从我们的应用程序中访问和操作，还可以从其他地方访问和操作。我们将开发一个数据模型类，封装我们的图书馆应用程序数据处理方法。然后这个类可以被其他应用程序使用。


# 第七章：一个高级示例

到目前为止，您应该能够使用 PDO 开发 Web 应用程序。但是，当应用程序保持相当小且功能有限时，我们的示例应用程序是可管理的。很快您将意识到，在一个文件中混合所有的数据访问、用户输入和显示逻辑可能会变得难以管理。

为了编写更易管理的代码，并允许多个开发人员共同开发项目，数据访问用户输入处理和页面呈现应该分开。您可能已经听说过广泛用于大型 Web 应用程序的**模型-视图-控制器**编程范式（MVC）。其思想是将数据访问和修改模块（即**模型**）与数据呈现（即**视图**）分开。视图可能非常复杂，因此通常使用模板引擎。最后，**控制器**是一个接收用户输入、访问模型并准备视图的 PHP 脚本。

除了使代码库更易管理外，这种划分还允许我们从其他应用程序（使用在应用程序自己的服务器上运行的维护脚本或在其他服务器上运行的脚本，通过 RPC 或 SOAP 调用访问）访问模型的功能。

由于 PDO 是面向对象的，并且可以从对`PDOStatement::fetch()`方法的调用中返回类的实例，因此我们将使用面向对象编程来模拟我们的数据实体（书籍、作者和借书记录）。

# 设计模型

模型通常由一个静态类组成（其方法被静态调用），以及模拟数据实体的几个类。对该模型类的方法的调用要么返回其他模型类的实例，要么返回`PDOStatement`实例，后者在调用`fetch()`方法时返回模型类的实例。

对于我们的应用程序，类将是`Model，Book，Author`和`Borrower`。这些类反映了我们示例数据库中的表，并允许我们对底层数据执行简单的操作。（主要思想是将 SQL 从控制器脚本中隔离到相关的模型类中。）例如，`Book`类可能有一个方法来返回一个代表该书的作者的`Author`类实例。另一方面，`Author`类可能有一个方法来返回一个由该作者撰写的每本书的`Book`类实例的列表。

在本章中，我们将开发我们自己的静态`Model`类以及`Book，Author`和`Borrower`类。在开始之前，我们应该清楚地定义每个类将具有的方法（功能）。让我们定义模型的功能。

`Model`类应包含静态方法，这些方法将充当数据库中存储的数据的*入口点*。这些方法应该执行以下操作：

+   获取所有的书籍。

+   获取所有的作者。

+   获取所有的书籍借阅者。

+   获取书籍的数量。

+   获取作者的数量。

+   获取书籍借阅者的数量。

+   按 ID 获取一本书。

+   按 ID 获取作者。

+   按 ID 获取借书人。

另一方面，`Model`类将不包含在书籍或作者上执行的方法。要借出一本书，我们将使用`Book`类中定义的方法，要归还一本书，我们将使用`Borrower`类中的方法。

现在让我们计划`Book`类的方法：

+   获取作者。

+   获取书籍的借书人列表。

+   借出一本书。

对于我们的示例应用程序，`Author`类甚至更简单：

+   获取所有的书籍。

+   获取该作者的书籍数量。

最后，还有代表借书人表中记录的`Borrower`类：

+   获取书籍。

+   返回书籍。

每个数据实体的属性将作为相关类的实例变量可访问。此外，这些类中的方法将包含我们已经在`books.php`和其他文件中编写的 PDO 调用。我们将这些方法移动到相关的类中，这些文件将只作为处理用户输入的控制器。表单验证仍然是控制器脚本的任务。但是，我们不打算将显示逻辑与业务逻辑分开，因为我们的应用程序非常简单，没有必要使用任何模板引擎，甚至将页面渲染代码移动到单独的**include**文件中。

除此之外，我们将不再使用全局变量`$conn`。`Model`类将有一个同名的私有静态变量和一个检索连接对象的方法。这个方法将遵循单例模式，并在需要时创建对象，如果尚未创建，则简单地返回它（有关单例模式的更多信息以及在 PHP5 中的示例实现，您可以访问[`en.wikipedia.org/wiki/Singleton_pattern`](http://en.wikipedia.org/wiki/Singleton_pattern)）。

我们将把所有类都放在一个名为`classes.inc.php`的单独文件中，然后从`common.inc.php`中包含它。

让我们从中心的`Model`类开始：

```php
/**
* This is the central Model class. Use its static methods
* To retrieve a book, author, borrower by ID
* Or all the books, authors and borrowers
*/
class Model
{
/**
* This is the connection object returned by
* Model::getConn()
* @var PDO
*/
private static $conn = null;
/**
* This method returns the connection object.
* If it has not been yet created, this method
* instantiates it based on the $connStr, $user and $pass
* global variables defined in common.inc.php
* @return PDO the connection object
*/
static function getConn()
{
if(!self::$conn) {
global $connStr, $user, $pass;
try
{
self::$conn = new PDO($connStr, $user, $pass);
self::$conn->setAttribute(PDO::ATTR_ERRMODE,
PDO::ERRMODE_EXCEPTION);
}
catch(PDOException $e)
{
showHeader('Error');
showError("Sorry, an error has occurred. Please
try your request later\n" . $e->getMessage());
}
}
return self::$conn;
}
/**
* This method returns the list of all books
* @return PDOStatement
*/
static function getBooks()
{
$sql = "SELECT * FROM books ORDER BY title";
$q = self::getConn()->query($sql);
$q->setFetchMode(PDO::FETCH_CLASS, 'Book', array());
return $q;
}
/**
* This method returns the number of books in the database
* @return int
*/
static function getBookCount()
{
$sql = "SELECT COUNT(*) FROM books";
$q = self::getConn()->query($sql);
$rv = $q->fetchColumn();
$q->closeCursor();
return $rv;
}
/**
*This method returns a book with given ID
* @param int $id
* @return Book
*/
static function getBook($id)
{
$id = (int)$id;
$sql = "SELECT * FROM books WHERE id=$id";
$q = self::getConn()->query($sql);
$rv = $q->fetchObject('Book');
$q->closeCursor();
return $rv;
}
/**
* This method returns the list of all authors
* @return PDOStatement
*/
static function getAuthors()
{
$sql = "SELECT * FROM authors ORDER BY lastName, firstName";
$q = self::getConn()->query($sql);
$q->setFetchMode(PDO::FETCH_CLASS, 'Author', array());
return $q;
}
/**
* This method returns the number of authors in the database
* @return int
*/
static function getAuthorCount()
{
$sql = "SELECT COUNT(*) FROM authors";
$q = self::getConn()->query($sql);
$rv = $q->fetchColumn();
$q->closeCursor();
return $rv;
}
/**
*This method returns an author with given ID
* @param int $id
* @return Author
*/
static function getAuthor($id)
{
$id = (int)$id;
$sql = "SELECT * FROM authors WHERE id=$id";
$q = Model::getConn()->query($sql);
$rv = $q->fetchObject('Author');
$q->closeCursor();
return $rv;
}
/**
* This method returns the list of all borrowers
* @return PDOStatement
*/
static function getBorrowers()
{
$sql = "SELECT * FROM borrowers ORDER BY dt";
$q = self::getConn()->query($sql);
$q->setFetchMode(PDO::FETCH_CLASS, 'Borrower', array());
return $q;
}
/**
* This method returns the number of borrowers in the database
* @return int
*/
static function getBorrowerCount()
{
$sql = "SELECT COUNT(*) FROM borrowers";
$q = self::getConn()->query($sql);
$rv = $q->fetchColumn();
$q->closeCursor();
return $rv;
}
/**
*This method returns a borrower with given ID
* @param int $id
* @return BorrowedBook
*/
static function getBorrower($id)
{
$id = (int)$id;
$sql = "SELECT * FROM borrowers WHERE id=$id";
$q = Model::getConn()->query($sql);
$rv = $q->fetchObject('Borrower');
$q->closeCursor();
return $rv;
}
}

```

正如您所见，这个类定义了`getConn()`方法，用于检索 PDO 连接对象，以及另外九个方法——每个数据实体（书籍、作者和借阅者）三个方法。获取所有数据实体的方法（`getBooks()`、`getAuthors()`和`getBorrowers()`）返回一个预配置为获取相关类实例的`PDOStatement`。返回每个数据实体的数量的方法获取一个整数，而返回单个数据实体的方法获取数据实体模型类的实例。请注意这些方法中如何关闭游标——这个功能已经从控制器文件中转移过来。

现在让我们来看看这三个模型类。

```php
/**
* This class represents a single book
*/
class Book
{
/**
* Return the author object for this book
* @return Author
*/
function getAuthor()
{
return Model::getAuthor($this->author);
}
/**
* This method is used to lend this book to the person
* specified by $name. It returns the Borrower class
* instance in case of success, or null in case when we cannot
* lend this book due to insufficient copies left
* @param string $name
* @return Borrower
*/
function lend($name)
{
$conn = Model::getConn();
$conn->beginTransaction();
try
{
$stmt = $conn->query("SELECT copies FROM books
WHERE id=$this->id");
$copies = $stmt->fetchColumn();
$stmt->closeCursor();
if($copies > 0) {
// If we can lend it
$conn->query("UPDATE books SET copies=copies-1
WHERE id=$this->id");
$stmt = $conn->prepare("INSERT INTO borrowers(book, name, dt)
VALUES(?, ?, ?)");
$stmt->execute(array($this->id, $name, time()));
// Success, get the newly created
// borrower ID
$bid = $conn->lastInsertId();
$rv = Model::getBorrower($bid);
}
else {
$rv = null;
}
$conn->commit();
}
catch(PDOException $e)
{
// Something bad happened
// Roll back and rethrow the exception
$conn->rollBack();
throw $e;
}
return $rv;
}
}

```

这里我们只有两个方法。一个用于获取书籍的作者（请注意我们在这里重用了`Model::getAuthor()`方法）。另一个方法提供了*借书*功能。请注意我们是从数据库中重新读取了副本列的值，而不是依赖于`$this->copies`变量。正如我们在上一章中看到的，这是为了确保数据完整性。`$this->copies`变量在事务开始之前就被赋值了，当调用`Book::lend()`方法时，数据库中的实际副本数量可能已经发生了变化。

这就是为什么我们在事务中再次读取该值。此外，如果操作失败，此方法将返回 null，如果操作成功，将返回`Borrower`类的实例。如果发生错误，将抛出一个异常，由`common.inc.php`中定义的异常处理程序处理（就像以前一样）。

另一个`model`类是`Author`。它非常简单：

```php
/**
* This class represents a single author
*/
class Author
{
/**
* This method returns the list of books
* written by this author
* @return PDOStatement
*/
function getBooks()
{
$sql = "SELECT * FROM books WHERE author=$this->id
ORDER BY title";
$q = Model::getConn()->query($sql);
$q->setFetchMode(PDO::FETCH_CLASS, 'Book', array());
return $q;
}
/**
* This method returns the number of books
* written by this author
* @return int
*/
function getBookCount()
{
$sql = "SELECT COUNT(*) FROM books WHERE author=$this->id";
$q = Model::getConn()->query($sql);
$rv = $q->fetchColumn();
$q->closeCursor();
return $rv;
}
}

```

这两个方法只是返回该作者写的书籍列表和此列表中的书籍数量。

最后，`Borrower`类表示借阅者表中的一条记录：

```php
/**
* This class represents a single borrower
* (i.e., a record in the borrowers table)
*/
class Borrower
{
/**
* Return the book associated with this borrower
* @return Book
*/
function getBook()
{
return Model::getBook($this->book);
}
/**
* This method "returns" a book.
* After this method call, this object
* is unusable as it does not represent
* a data entity any more
*/
function returnBook()
{
$conn = Model::getConn();
$conn->beginTransaction();
try
{
$book = $this->getBook();
$conn->query("DELETE FROM borrowers WHERE id=$this->id");
$conn->query("UPDATE books SET copies=copies+1
WHERE id=$book->id");
$conn->commit();
}
catch(PDOException $e)
{
$conn->rollBack();
throw $e;
}
}
}

```

实质上，`returnBook()`方法的主体是从`returnBook.php`文件中转移过来的（就像`Book::lend()`方法是从`lendBook.php`文件中稍作修改后转移过来的一样）。

# 修改前端以使用模型

现在我们已经从生成前端页面的文件中删除了数据访问逻辑，让我们看看应该如何修改它们。让我们从`books.php`文件开始：

```php
<?php
/**
* This page lists all the books we have
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Display the header
showHeader('Books');
**// Get the books list
$books = Model::getBooks();**
// now create the table
?>
**Total books: <?=Model::getBookCount()?>**
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Cover</td>
<td>Author and Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
<td>Copies</td>
<td>Lend</td>
<td>Edit</td>
</tr>
<?php
// Now iterate over every row and display it
**while($b = $books->fetch())
{
$a = $b->getAuthor();**
?>
<tr>
<td>
<?php if($b->coverMime) { ?>
**<img src="showCover.php?book=<?=$b->id?>">**
<?php } else { ?>
n/a
<? } ?>
</td>
<td>
**<a href="author.php?id=<?=$a->id?>"><?=htmlspecialchars("$a >firstName $a->lastName")?></a><br/>
<b><?=htmlspecialchars($b->title)?></b>
</td>
<td><?=htmlspecialchars($b->isbn)?></td>
<td><?=htmlspecialchars($b->publisher)?></td>
<td><?=htmlspecialchars($b->year)?></td>
<td><?=htmlspecialchars($b->summary)?></td>
<td><?=$b->copies?></td>
<td>
<a href="lendBook.php?book=<?=$b->id?>">Lend</a>
</td>
<td>
<a href="editBook.php?book=<?=$b->id?>">Edit</a>
</td>**
</tr>
<?php
}
?>
</table>
<a href="editBook.php">Add book...</a>
<?php
// Display footer
showFooter();

```

如您所见，我们已经删除了 SQL 命令和对 PDO 类实例方法的调用，并用`Model`类的方法调用替换了它们（请注意突出显示的行）。

另一个重要的变化是，在`while`循环中返回的`Book`类的实例（从第 30 行开始）没有作者的名字或姓氏的变量。为了获取这些变量，我们为我们显示的每一本书调用`Book::getAuthor()`方法。然后，在循环的后面，我们引用`$b`变量来访问书的属性，或者引用`$a`变量来访问作者的详细信息。请注意，我们在这里访问这些细节时，是作为对象变量而不是数组元素。

这是因为`Model::getBooks()`方法不再使用表连接，所以`Book`类的实例不会包含作者的详细信息。相反，`Book`类定义了一个方法来获取该书的`Author`对象。这意味着，对于我们显示的每一本书，我们将执行额外的 SQL 查询来获取作者的详细信息。

乍一看，这可能在性能上显得过于昂贵。但另一方面，在实际应用中，我们可能只会显示表中的一页（比如说，20 本书），而表中可能有数千条记录。在这种情况下，一个在`books`表上没有`JOIN`的`SELECT`语句，选择要在当前页面显示的行，然后对每一行进行一些简单的查询，可能更有效率。

然而，如果这种方法不合适，那么`Model`类可以扩展另一个方法，例如`Model::getBooksWithAuthors()`，它将返回`Book`类的实例，其中`lastName`和`firstName`变量将存在。这个方法可能看起来像下面这样：

```php
/**
* This method returns the list of all books with
* author's first and last names
* @return PDOStatement
*/
static function getBooksWithAuthors()
{
$sql = "SELECT books.*, authors.lastName, authors.firstName
FROM books, authors
WHERE books.author=authors.id
ORDER BY title";
$q = self::getConn()->query($sql);
$q->setFetchMode(PDO::FETCH_CLASS, 'Book', array());
return $q;
}

```

开发模型部分可能会在灵活性方面对我们施加限制，但这是为了代码可管理性而付出的代价。然而，这可以通过模型类中的其他方法或者如果真的有必要的话，通过与 PDO 的直接通信来克服。上述方法是可能的，因为 PDO 不关心类中定义了哪些变量；它只是动态地为查询返回的每一列创建变量。

当谨慎使用时，这是一个非常强大的功能。如果不小心使用，可能会导致难以跟踪的逻辑错误。例如，如果在上述方法中从作者表中选择了`ID`列，那么它的值将覆盖从书表中选择的`ID`列的值。`Book`类中的其他方法依赖于`id`字段中的值是正确的，如果这个值不正确，可能会导致严重的数据损坏。

我们现在应该修改的另一个文件是`authors.php:`

```php
<?php
/**
* This page lists all the authors we have
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Display the header
showHeader('Authors');
// Get number of authors and issue the query
**$authors = Model::getAuthors();**
// now create the table
?>
**Total authors: <?=Model::getAuthorCount()?>**
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>First Name</td>
<td>Last Name</td>
<td>Bio</td>
<td>Edit</td>
</tr>
<?php
// Now iterate over every row and display it
**while($a = $authors->fetch())
{**
?>
<tr>
**<td><?=htmlspecialchars($a->firstName)?></td>
<td><?=htmlspecialchars($a->lastName)?></td>
<td><?=htmlspecialchars($a->bio)?></td>
<td>
<a href="editAuthor.php?author=<?=$a->id?>">Edit</a>
</td>**
</tr>
<?php
}
?>
</table>
<a href="editAuthor.php">Add Author...</a>
<?php
// Display footer
showFooter();

```

在这里，我们只是用对`Model`类的调用替换了与 PDO 的直接通信，并重写了循环以使用对象变量而不是数组元素。

对应用程序所做的更改还允许我们从`author.php:`中删除与 SQL 相关的代码片段。

```php
<?php
/**
* This page shows an author's profile
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Get the author
$id = (int)$_REQUEST['id'];
**$author = Model::getAuthor($id);**
// Now see if the author is valid - if it's not,
// we have an invalid ID
if(!$author) {
showHeader('Error');
echo "Invalid Author ID supplied";
showFooter();
exit;
}
// Display the header - we have no error
**showHeader("Author: $author->firstName $author->lastName");**
// Now get the number and fetch all his books
**$books = $author->getBooks();
$totalBooks = $author->getBookCount();**
// now display everything
?>
<h2>Author</h2>
<table width="60%" border="1" cellpadding="3">
<tr>
<td><b>First Name</b></td>
**<td><?=htmlspecialchars($author->firstName)?></td>**
</tr>
<tr>
<td><b>Last Name</b></td>
**<td><?=htmlspecialchars($author->lastName)?></td>**
</tr>
<tr>
<td><b>Bio</b></td>
**<td><?=htmlspecialchars($author->bio)?></td>**
</tr>
<tr>
<td><b>Total books</td>
<td><?=$totalBooks?></td>
</tr>
</table>
**<a href="editAuthor.php?author=<?=$author->id?>">Edit author...</a>**
<h2>Books</h2>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Title</td>
<td>ISBN</td>
<td>Publisher</td>
<td>Year</td>
<td>Summary</td>
</tr>
<?php
// Now iterate over every book and display it
**while($b = $books->fetch())
{**
?>
<tr>
**<td><?=htmlspecialchars($b->title)?></td>
<td><?=htmlspecialchars($b->isbn)?></td>
<td><?=htmlspecialchars($b->publisher)?></td>
<td><?=htmlspecialchars($b->year)?></td>
<td><?=htmlspecialchars($b->summary)?></td>**
</tr>
<?php
}
?>
</table>
<?php
// Display footer
showFooter();

```

这里的变化相当表面，它只是删除了与 PDO 的直接通信，并将高亮显示的行上的*数组*语法更改为*对象*语法。

最后，显示`borrowers.php`中的列表的最后一个页面：

```php
<?php
/**
* This page lists all borrowed books
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Display the header
showHeader('Lended Books');
// Get all lended books list
**$brs = Model::getBorrowers();
$totalBooks = Model::getBorrowerCount();**
// now create the table
?>
Total borrowed books: <?=$totalBooks?>
<table width="100%" border="1" cellpadding="3">
<tr style="font-weight: bold">
<td>Title</td>
<td>Author</td>
<td>Borrowed by</td>
<td>Borrowed on</td>
<td>Return</td>
</tr>
<?php
// Now iterate over every row and display it
**while($br = $brs->fetch())
{
$b = $br->getBook();
$a = $b->getAuthor();**
?>
<tr>
**<td><?=htmlspecialchars($b->title)?></td>
<td><?=htmlspecialchars("$a->firstName $a->lastName")?></td>
<td><?=htmlspecialchars($br->name)?></td>
<td><?=date('d M Y', $br->dt)?></td>
<td>
<a href="returnBook.php?borrower=<?=$br->id?>">Return</a>
</td>**
</tr>
<?php
}
?>
</table>
<?php
// Display footer
showFooter();

```

在这个文件中，我们遇到了与`books.php`页面相同的问题——`Model`类返回的`Borrower`类实例没有书名和作者名，而我们希望在这个页面上显示。因此，我们在每次迭代中为每个`Borrower`类实例获取`Book`类实例，然后使用该对象获取作者的详细信息。

最后，我们将修改另外两个页面，以利用我们新创建的数据模型。这两个页面是`lendBook.php`和`returnBook.php`。它们可能包含了与 PDO 交互的最长的代码段。从`lendBook.php`中，我们移除了事务内部的所有代码：

```php
<?php
/**
* This page allows you to lend a book
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// First see if the request contains the book ID
// Return to books.php if the ID invalid
$id = (int)$_REQUEST['book'];
**$book = Model::getBook($id);**
if(!$book) {
header("Location: books.php");
exit;
}
// Now see if the form was submitted
$warnings = array();
if($_POST['submit']) {
// Require that the borrower's name is entered
if(!$_POST['name']) {
$warnings[] = 'Please enter borrower\'s name';
}
else {
**// Form is OK, "lend" the book
if(!$book->lend($_POST['name'])) {
// Failure, show error message
$warnings[] = 'There are no more copies of
this book available';
}**
}
// Now, if we don't have errors,
// redirect back to books.php
if(count($warnings) == 0) {
header("Location: books.php");
exit;
}
// Otherwise, the warnings will be displayed
}
// Display the header
showHeader('Lend Book');
// If we have any warnings, display them now
if(count($warnings)) {
echo "<b>Please correct these errors:</b><br>";
foreach($warnings as $w)
{
echo "- ", htmlspecialchars($w), "<br>";
}
}
// Now display the form
?>
<form action="lendBook.php" method="post">
<input type="hidden" name="book" value="<?=$id?>">
<b>Please enter borrower's name:<br></b>
<input type="text" name="name" value="<?=htmlspecialchars($_
POST['name'])?>">
<input type="submit" name="submit" value=" Lend book ">
</form>
<?php
// Display footer
showFooter();

```

注意我们如何改变了*借出*图书的部分——`Bool::lend()`方法在失败的情况下返回`null`，因此我们将显示没有更多可借的书的消息。如果操作成功，那么`Book::lend()`方法将返回`Borrower`类实例（在`if`语句中求值为`true`），页面将重定向到`books.php`。

类似地，我们从`returnBook.php`中删除了与 PDO 相关的代码，并用相应的调用`Borrower::returnBook()`方法替换：

```php
<?php
/**
* This page "returns" a book back to the library
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// First see if the request contains the borrowers ID
// Return to books.php if not
$id = (int)$_REQUEST['borrower'];
**$borrower = Model::getBorrower($id);**
if(!$borrower) {
header("Location: books.php");
exit;
}
// Return the book and redirect to books.php
// If anything happens, the exception will be
// handled automatically
**$borrower->returnBook();**
header("Location: books.php");

```

# 分离模型的优势

到目前为止，几乎所有生成前端页面的文件都不包含数据访问逻辑，更容易管理。另一方面，模型类可以从我们的应用程序外部使用，并且可以快速创建额外的页面来以其他格式（如 XML）表示数据库中的信息。

例如，考虑以下页面（我们将其称为`books.xml.php`）：

```php
<?php
/**
* This page lists all the books we have as an XML data structure
* PDO Library Management example application
* @author Dennis Popel
*/
// Don't forget the include
include('common.inc.php');
// Set the content type to be XML
header('Content-Type: application/xml');
// Get the books list
$books = Model::getBooksWithAuthors();
// Echo XML declaration and open root element
echo '<?xml version="1.0"?>', "\n";
echo "<books>\n";
// Now iterate over every book and display it
while($b = $books->fetch())
{
?>
<book id="<?=$b->id?>">
<isbn><?=$b->isbn?></isbn>
<title><?=htmlspecialchars($b->title)?></title>
<publisher><?=htmlspecialchars($b->publisher)?></publisher>
<summary><?=htmlspecialchars($b->summary)?></summary>
<author>
<id><?=$b->author?></id>
<lastName><?=$b->lastName?></lastName>
<firstName><?=$b->firstName?></firstName>
</author>
</book>
<?
}
echo '</books>';

```

这个文件允许我们以 XML 格式导出书籍列表，供另一个应用程序使用。正如你所看到的，对原始的`books.php`文件的更改只在显示逻辑中。如果你现在导航到该页面，你应该会看到以下内容：

![分离模型的优势](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrn-php-data-obj/img/2660_07_01.jpg)

通过轻微修改，我们能够创建数据的新表示（第二和第三本书已经折叠以适应截图）。

定义`model`类的另一个优势是，这些类成为数据访问和操作的中心点。例如，如果你改变了用于表示来自多个表的数据的 SQL（使用连接）或找到了优化查询的方法，你只需要更新相关的模型类，使用该查询的脚本（控制器）就不需要更新。这是一个重要的可管理性优势。

你可以扩展抽象模型类，以模拟通用数据模型中真实子类的扩展功能。例如，在内容管理系统中，你可以创建一个名为`Item`的抽象基类，它将为所有子类（项目类型）具有共同的属性，如作者、关键词和创建日期。然后模型可以对所有可能的子类执行一些操作，而无需进一步编码，以便广泛重用现有代码。

有一种叫做**对象关系映射器**（**ORMs**）的工具，它们利用了本章描述的思想。ORMs 用于创建功能强大的面向对象应用程序，在这些应用程序中，你的模型中几乎没有 SQL 代码。（事实上，这些工具在一些配置后扮演了你应用程序中的模型的角色。）你可以在[`en.wikipedia.org/wiki/Object-relational_mapping`](http://en.wikipedia.org/wiki/Object-relational_mapping)了解更多关于 ORMs 的信息。Propel ([`propel.phpdb.org/`](http://propel.phpdb.org/))是 PHP5 的一种流行的 ORM 工具。

# 进一步思考

本章开发的模型在至少两个领域需要一些改进，如果你想在实际应用中使用它的话。我们没有在模型中创建能够提供`editBook.php`和`editAuthor.php`文件功能的方法。然而，现在你应该准备自己添加这些功能。我们将为你提供一些提示：

+   创建`Book::update()`和`Author::update()`方法。这些方法应该接受反映每个对象属性的参数（对于`Author`类，这应该是名字、姓氏和传记）。

+   这些方法应该使用预处理语句来更新数据库中相应的记录（基于`$this->id`的值）。

+   `Model`类应该扩展两个方法，`Model::createBook()`和`Model::createAuthor()`。这些方法应该接受与`Book::update()`和`Author::update()`相同的参数列表。两者都应该根据传递的参数插入一行到相关表中。可以使用以下代码完成这个操作：

```php
$conn = self::getConn();
$conn->beginTransaction();
try
{
$conn->query("INSERT INTO authors(bio) VALUES('')");
$aid = $conn->lastInsertId();
$author = self::getAuthor($aid);
$author->update($firstName, $lastName, $bio);
$conn->commit();
}
catch(Exception $e)
{
$conn->rollBack();
}

```

+   这里的想法是将实体更新集中在一个地方，即`Author::update()`。我们在这里使用事务来确保，如果发生任何事情，空行不会存储在数据库中。

+   表单处理代码应该检测它是在编辑现有实体还是创建新实体，并在已经存在的实例上适当地调用`Model::createAuthor()`或`Author::update()`。

另一个问题是，模型类的方法不验证接受的参数。如果要将数据模型暴露给第三方应用程序，它们应该对传递到数据库的每个参数进行验证。如果通过 Web 浏览器访问，我们的数据模型受到表单验证代码的保护。然而，直接访问模型类并不那么安全。

建议在模型方法中接受用户提供的参数时，如果验证失败，抛出异常。此外，Web 表单验证和方法参数验证应该使用通用代码。（例如，您可以开发一个`Validation`类，无论值来自何处，都可以用来验证。）这段代码应该从表单验证代码和模型方法中使用。通过这样做，您将确保代码重用和验证规则的单一位置。

# 收尾工作

PHP 数据对象是一种很棒且易于使用的技术。然而，它仍处于起步阶段，许多改进和其他变化尚未到来。一定要及时了解来自 PHP 开发人员和大量 PHP 粉丝和用户的最新消息。

只有对安全威胁有深刻的理解并知道如何防范，才能有效地使用 PDO 和 PHP。使用 PDO 的预处理语句可以减少 SQL 注入攻击的风险，但作为开发人员，您仍然负责保护您的应用程序。确保您及时了解安全领域的最新发展。

愉快的 PHP 编程！
