# 现代化遗留的 PHP 应用（四）

> 原文：[`zh.annas-archive.org/md5/06777b89258a8f4db4e497a7883acfb3`](https://zh.annas-archive.org/md5/06777b89258a8f4db4e497a7883acfb3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 B. 门户网站之前的代码

本附录显示了一个遗留应用程序的部分页面脚本。它已经经过清理和匿名化处理，不是来自实际应用程序的。

这个脚本是系统的一部分，允许新闻学生撰写文章进行审查，并为其他学生的文章提供反馈。学生们可以为其他学生提供“积分”来审查他们的作品，并通过审查其他学生的文章来获得积分。由于积分是按审查支付的，学生们会限制最大审查次数，以确保他们不会用完积分。最后，他们被允许提供注释，指出审阅者应该注意的事项。

这是页面脚本在转换为使用网关类之前的版本。它只包含领域逻辑和数据源交互，而不包括初步设置或任何显示代码。

```php
1 <?php
2 // ...
3 require 'includes/setup.php';
4 // ...
5
6 $article_types = array(1, 2, 3, 4, 5);
7 $failure = array();
8 $now = time();
9
10 // sanitize and escape the user input
11 $input = $_POST;
12 $input['body'] = strip_tags($input['body']);
13 $input['notes'] = strip_tags($input['notes']);
14 foreach ($input as $key => $val) {
15 $input[$key] = mysql_real_escape_string($val);
16 }
17
18 if (isset($input['ready']) && $input['ready'] == 'on') {
19 $input['ready'] = 1;
20 } else {
21 $input['ready'] = 0;
22 }
23
24 // nothing less than 0.01 credits per rating
25 $input['credits_per_rating'] = round(
26 $input['credits_per_rating'],
27 2
28 );
29
30 $credits = round(
31 $input['credits_per_rating'] * $input['max_ratings'],
32 2
33 );
34
35 // updating an existing article?
36 if ($input['id']) {
37
38 // make sure this article belongs to the user
39 $stm = "SELECT *
40 FROM articles
41 WHERE user_id = '{$user_id}'
42 AND id = '{$input['id']}'
43 LIMIT 1";
44 $result = mysql_query($stm);
45
46 if (mysql_num_rows($result)) {
47
48 // get the existing article from the database
49 $row = mysql_fetch_assoc($result);
50
51 // don't charge unless the article is ready
52 $decrement = false;
53
54 // is the article marked as ready?
55 if ($input['ready'] == 1) {
56
57 // did they offer at least the minimum?
58 if (
59 $credits > 0
60 && $input['credits_per_rating'] >= 0.01
61 && is_numeric($credits)
62 ) {
63
64 // was the article previously ready for review?
65 // (note 'row' not 'input')
66 if ($row['ready'] == 1) {
67
68 // only subtract (or add back) the difference to their
69 // account, since they already paid something
70 if (
71 is_numeric($row['credits_per_rating'])
72 && is_numeric($row['max_ratings'])
73 ) {
74 // user owes $credits, minus whatever they paid already
75 $amount = $row['credits_per_rating']
76 * $row['max_ratings']
77 $credits = $credits - $amount;
78 }
79
80 $decrement = true;
81
82 } else {
83 // article not ready previously, so they hadn't
84 // had credits deducted. if this is less than their
85 // in their account now, they may proceed.
86 $residual = $user->get('credits') - $credits;
87 $decrement = true;
88 }
89
90 } else {
91 $residual = -1;
92 $failure[] = "Credit offering invalid.";
93 $decrement = false;
94 }
95
96 } else {
97
98 // arbitrary positive value; they can proceed
99 $residual = 1;
100
101 // if it was previously ready but is no longer, refund them
102 if (
103 is_numeric($row['credits_per_rating'])
104 && is_numeric($row['max_ratings'])
105 && ($row['ready'] == 1)
106 ) {
107 // subtract a negative value
108 $amount = $row['credits_per_rating']
109 * $row['max_ratings']
110 $credits = -($amount);
111 $decrement = true;
112 }
113 }
114
115 if ($residual >= 0) {
116
117 if (strlen($input['notes'])>0) {
118 $notes = "notes = '{$input['notes']}'";
119 } else {
120 $notes = "notes = NULL";
121 }
122
123 if (strlen($input['title'])>0) {
124 $title = "title = '{$input['title']}'";
125 } else {
126 $title = "title = NULL";
127 }
128
129 if (! in_array(
130 $input['article_type'],
131 $article_types
132 )) {
133 $input['article_type'] = 1;
134 }
135
136 $stm = "UPDATE articles
137 SET
138 body = '{$input['body']}',
139 $notes,
140 $title,
141 article_type = '{$input['article_type']}',
142 ready = '{$input['ready']}',
143 last_edited = '{$now}',
144 ip = '{$_SERVER['REMOTE_ADDR']}',
145 credits_per_rating = '{$input['credits_per_rating']}',
146 max_ratings = '{$input['max_ratings']}'
147 WHERE user_id = '{$user_id}'
148 AND id = '{$input['id']}'";
149
150 if (mysql_query($stm)) {
151 $article_id = $input['id'];
152
153 if ($decrement) {
154 // Charge them
155 $stm = "UPDATE users
156 SET credits = credits - {$credits}
157 WHERE user_id = '{$user_id}'";
158 mysql_query($stm);
159 }
160 } else {
161 $failure[] = "Could not update article.";
162 }
163 } else {
164 $failure[] = "You do not have enough credits for ratings.";
165 }
166 }
167
168 } else {
169
170 // creating a new article. do not decrement until specified.
171 $decrement = false;
172
173 // if the article is ready, we need to subtract credits.
174 if ($input['ready'] == 1) {
175
176 // if this is greater than or equal to 0, they may proceed.
177 if (
178 $credits > 0
179 && $input['credits_per_rating']>=0.01
180 && is_numeric($credits)
181 ) {
182 // minimum offering is 0.01
183 $residual = $user->get('credits') - $credits;
184 $decrement = true;
185 } else {
186 $residual = -1;
187 $failure[] = "Credit offering invalid.";
188 }
189
190 } else {
191 // arbitrary positive value if they are not done with their article.
192 // no deduction made yet.
193 $residual = 1;
194 }
195
196 // can user afford ratings on the new article?
197 if ($residual >= 0) {
198
199 // yes, insert the article
200 $stm = "INSERT INTO articles (
201 user_id,
202 ip,
203 last_edited,
204 article_type
205 ) VALUES (
206 '{$user_id}',
207 '{$_SERVER['REMOTE_ADDR']}',
208 '$now',
209 '$input['article_type']'
210 )";
211
212 if (mysql_query($stm)) {
213 $article_id = mysql_insert_id();
214 if ($decrement) {
215 // Charge them
216 $stm = "UPDATE users
217 SET credits = credits - {$credits}
218 WHERE user_id='{$user_id}'";
219 mysql_query($stm);
220 }
221 } else {
222 $failure[] = "Could not update credits.";
223 }
224
225 $stm = "UPDATE articles
226 SET
227 body = '{$input['body']}',
228 $notes,
229 $title,
230 article_type = '{$input['article_type']}',
231 ready = '{$input['ready']}',
232 last_edited = '$now',
233 ip = '{$_SERVER['REMOTE_ADDR']}',
234 credits_per_rating = '{$input['credits_per_rating']}',
235 max_ratings = '{$input['max_ratings']}'
236 WHERE
237 user_id = '{$user_id}'
238 AND id = '$article_id'
239 ";
240
241 if (! mysql_query($stm)) {
242 $failure[] = "Could not update article.";
243 }
244
245 } else {
246
247 // cannot afford ratings on new article
248 $failure[] = "You do not have enough credits for ratings.";
249 }
250 }
251 ?>
```


# 附录 C. 网关后的代码

本附录显示了附录 B 中页面脚本在转换为使用网关类之后的版本。请注意，它几乎没有改变。尽管 SQL 语句已被移除，但领域业务逻辑仍嵌入在页面脚本中。

网关类在页面脚本下面提供，并显示了转换为 PDO 风格绑定参数。还要注意，页面脚本中的`if()`条件已经进行了微小的修改：以前它们检查查询是否成功，现在它们检查网关的返回值。

```php
**page_script.php**
<?php
2 // ... $user_id value created earlier
3
4 $db = new Database($db_host, $db_user, $db_pass);
5 $articles_gateway = new ArticlesGateway($db);
6 $users_gateway = new UsersGateway($db);
7
8 $article_types = array(1, 2, 3, 4, 5);
9 $failure = array();
10 $now = time();
11
12 // sanitize and escape the user input
13 $input = $_POST;
14 $input['body'] = strip_tags($input['body']);
15 $input['notes'] = strip_tags($input['notes']);
16
17 if (isset($input['ready']) && $input['ready'] == 'on') {
18 $input['ready'] = 1;
19 } else {
20 $input['ready'] = 0;
21 }
22
23 // nothing less than 0.01 credits per rating
24 $input['credits_per_rating'] = round(
25 $input['credits_per_rating'],
26 2
27 );
28
29 $credits = round(
30 $input['credits_per_rating'] * $input['max_ratings'],
31 2
32 );
33
34 // updating an existing article?
35 if ($input['id']) {
36
37 $row = $articles_gateway->selectOneByIdAndUserId($input['id'], $user_id);
38
39 if ($row) {
40
41 // don't charge unless the article is ready
42 $decrement = false;
43
44 // is the article marked as ready?
45 if ($input['ready'] == 1) {
46
47 // did they offer at least the minimum?
48 if (
49 $credits > 0
50 && $input['credits_per_rating'] >= 0.01
51 && is_numeric($credits)
52 ) {
53
54 // was the article previously ready for review?
55 // (note 'row' not 'input')
56 if ($row['ready'] == 1) {
57
58 // only subtract (or add back) the difference to their
59 // account, since they already paid something
60 if (
61 is_numeric($row['credits_per_rating'])
62 && is_numeric($row['max_ratings'])
63 ) {
64 // user owes $credits, minus whatever they paid already
65 $amount = $row['credits_per_rating']
66 * $row['max_ratings']
67 $credits = $credits - $amount;
68 }
69
70 $decrement = true;
71
72 } else {
73 // article not ready previously, so they hadn't
74 // had credits deducted. if this is less than their
75 // in their account now, they may proceed.
76 $residual = $user->get('credits') - $credits;
77 $decrement = true;
78 }
79
80 } else {
81 $residual = -1;
82 $failure[] = "Credit offering invalid.";
83 $decrement = false;
84 }
85
86 } else {
87
88 // arbitrary positive value; they can proceed
89 $residual = 1;
90
91 // if it was previously ready but is no longer, refund them
92 if (
93 is_numeric($row['credits_per_rating'])
94 && is_numeric($row['max_ratings'])
95 && ($row['ready'] == 1)
96 ) {
97 // subtract a negative value
98 $amount = $row['credits_per_rating']
99 * $row['max_ratings']
100 $credits = -($amount);
101 $decrement = true;
102 }
103 }
104
105 if ($residual >= 0) {
106
107 $input['ip'] = $_SERVER['REMOTE_ADDR'];
108 $input['last_edited'] = $now;
109
110 if (! in_array(
111 $input['article_type'],
112 $article_types
113 )) {
114 $input['article_type'] = 1;
115 }
116
117 $result = $articles_gateway->updateByIdAndUserId(
118 $input['id'],
119 $user_id,
120 $input
121 );
122
123 if ($result) {
124 $article_id = $input['id'];
125
126 if ($decrement) {
127 $users_gateway->decrementCredits($user_id, $credits);
128 }
129 } else {
130 $failure[] = "Could not update article.";
131 }
132 } else {
133 $failure[] = "You do not have enough credits for ratings.";
134 }
135 }
136
137 } else {
138
139 // creating a new article. do not decrement until specified.
140 $decrement = false;
141
142 // if the article is ready, we need to subtract credits.
143 if ($input['ready'] == 1) {
144
145 // if this is greater than or equal to 0, they may proceed.
146 if (
147 $credits > 0
148 && $input['credits_per_rating']>=0.01
149 && is_numeric($credits)
150 ) {
151 // minimum offering is 0.01
152 $residual = $user->get('credits') - $credits;
153 $decrement = true;
154 } else {
155 $residual = -1;
156 $failure[] = "Credit offering invalid.";
157 }
158
159 } else {
160 // arbitrary positive value if they are not done with their article.
161 // no deduction made yet.
162 $residual = 1;
163 }
164
165 // can user afford ratings on the new article?
166 if ($residual >= 0) {
167
168 // yes, insert the article
169 $input['last_edited'] = $now;
170 $input['ip'] = $_SERVER['REMOTE_ADDR'];
171 $article_id = $articles_gateway->insert($input);
172
173 if ($article_id) {
174 if ($decrement) {
175 // Charge them
176 $users_gateway->decrementCredits($user_id, $credits);
177 }
178 } else {
179 $failure[] = "Could not update credits.";
180 }
181
182 $result = $articles_gateway->updateByIdAndUserId(
183 $article_id,
184 $user_id,
185 $input
186 );
187
188 if (! $result) {
189 $failure[] = "Could not update article.";
190 }
191
192 } else {
193
194 // cannot afford ratings on new article
195 $failure[] = "You do not have enough credits for ratings.";
196 }
197 }
198 ?>
```

```php
**classes/Domain/Articles/ArticlesGateway.php**
1 <?php
2 namespace Domain\Articles;
3
4 class ArticlesGateway
5 {
6 protected $db;
7
8 public function __construct(Database $db)
9 {
10 $this->db = $db;
11 }
12
13 public function selectOneByIdAndUserId($id, $user_id)
14 {
15 $stm = "SELECT *
16 FROM articles
17 WHERE user_id = :user_id
18 AND id = :id
19 LIMIT 1";
20
21 return $this->db->query($stm, array(
22 'id' => $id,
23 'user_id' => $user_id,
24 ))
25 }
26
27 public function updateByIdAndUserId($id, $user_id, $input)
28 {
29 if (strlen($input['notes']) > 0) {
30 $notes = "notes = :notes";
31 } else {
32 $notes = "notes = NULL";
33 }
34
35 if (strlen($input['title']) > 0) {
36 $title = "title = :title";
37 } else {
38 $title = "title = NULL";
39 }
40
41 $input['id'] = $id;
42 $input['user_id'] = $user_id;
43
44 $stm = "UPDATE articles
45 SET
46 body = :body,
47 $notes,
48 $title,
49 article_type = :article_type,
50 ready = :ready,
51 last_edited = :last_edited,
52 ip = :ip,
53 credits_per_rating = :credits_per_rating,
54 max_ratings = :max_ratings
55 WHERE user_id = :user_id
56 AND id = :id";
57
58 return $this->query($stm, $input);
59 }
60
61 public function insert($input)
62 {
63 $stm = "INSERT INTO articles (
64 user_id,
65 ip,
66 last_edited,
67 article_type
68 ) VALUES (
69 :user_id,
70 :ip,
71 :last_edited,
72 :article_type
73 )";
74 $this->db->query($stm, $input);
75 return $this->db->lastInsertId();
76 }
77 }
78 ?>
```

```php
**classes/Domain/Users/UsersGateway.php**
1 <?php
2 namespace Domain\Users;
3
4 class UsersGateway
5 {
6 protected $db;
7
8 public function __construct(Database $db)
9 {
10 $this->db = $db;
11 }
12
13 public function decrementCredits($user_id, $credits)
14 {
15 $stm = "UPDATE users
16 SET credits = credits - :credits
17 WHERE user_id = :user_id";
18 $this->db->query($stm, array(
19 'user_id' => $user_id,
20 'credits' => $credits,
21 ));
22 }
23 }
24 ?>
```


# 附录 D. 事务脚本后的代码

本附录展示了从附录 B 和 C 中提取领域逻辑到*Transactions*类的代码版本。请注意原始页面脚本现在被简化为对象创建和注入机制，并将大部分逻辑交给*Transactions*类处理。还请注意，现在`$failure`、`$credits`和`$article_types`变量现在是*Transactions*类的属性，而规范化/清理逻辑和信用计算逻辑是*Transactions*逻辑的一部分。

```php
**page_script.php**
<?php
2
3 // ... $user_id value created earlier
4
5 $db = new Database($db_host, $db_user, $db_pass);
6 $articles_gateway = new ArticlesGateway($db);
7 $users_gateway = new UsersGateway($db);
8 $article_transactions = new ArticleTransactions(
9 $articles_gateway,
10 $users_gateway
11 );
12
13 if ($_POST['id']) {
14 $article_transactions->updateExistingArticle($user_id, $_POST);
15 } else {
16 $article_transactions->submitNewArticle($user_id, $_POST);
17 }
18
19 $failure = $article_transactions->getFailure();
20 ?>
```

```php
**classes/Domain/Articles/ArticleTransactions.php**
1 <?php
2 namespace Domain\Articles;
3
4 use Domain\Users\UsersGateway;
5
6 class ArticleTransactions
7 {
8 protected $article_types = array(1, 2, 3, 4, 5);
9
10 protected $failure = array();
11
12 protected $input = array();
13
14 public function __construct(
15 ArticlesGateway $articles_gateway,
16 UsersGateway $users_gateway
17 ) {
18 $this->articles_gateway = $articles_gateway;
19 $this->users_gateway = $users_gateway;
20 }
21
22 public function getInput()
23 {
24 return $this->input;
25 }
26
27 public function getFailure()
28 {
29 return $this->failure;
30 }
31
32 public function getCredits()
33 {
34 return round(
35 $this->input['credits_per_rating'] * $this->input['max_ratings'],
36 2
37 );
38 }
39
40 public function filterInput($input)
41 {
42 $input['body'] = strip_tags($input['body']);
43 $input['notes'] = strip_tags($input['notes']);
44
45 if (isset($input['ready']) && $input['ready'] == 'on') {
46 $input['ready'] = 1;
47 } else {
48 $input['ready'] = 0;
49 }
50
51 // nothing less than 0.01 credits per rating
52 $input['credits_per_rating'] = round(
53 $input['credits_per_rating'],
54 2
55 );
56
57 // return the filtered input
58 return $input;
59 }
60
61 public function updateExistingArticle($user_id, $input)
62 {
63 $this->input = $this->filterInput($input);
64 $now = time();
65 $this->failure = array();
66 $credits = $this->getCredits();
67
68 $row = $this->articles_gateway->selectOneByIdAndUserId(
69 $this->input['id'],
70 $user_id
71 );
72
73 if ($row) {
74
75 // don't charge unless the article is ready
76 $decrement = false;
77
78 // is the article marked as ready?
79 if ($this->input['ready'] == 1) {
80
81 // did they offer at least the minimum?
82 if (
83 $credits > 0
84 && $this->input['credits_per_rating'] >= 0.01
85 && is_numeric($credits)
86 ) {
87
88 // was the article previously ready for review?
89 // (note 'row' not 'input')
90 if ($row['ready'] == 1) {
91
92 // only subtract (or add back) the difference to their
93 // account, since they already paid something
94 if (
95 is_numeric($row['credits_per_rating'])
96 && is_numeric($row['max_ratings'])
97 ) {
98 // user owes $credits, minus whatever they paid
99 // already
100 $amount = $row['credits_per_rating']
101 * $row['max_ratings']
102 $credits = $credits - $amount;
103 }
104
105 $decrement = true;
106
107 } else {
108 // article not ready previously, so they hadn't
109 // had credits deducted. if this is less than their
110 // in their account now, they may proceed.
111 $residual = $user->get('credits') - $credits;
112 $decrement = true;
113 }
114
115 } else {
116 $residual = -1;
117 $this->failure[] = "Credit offering invalid.";
118 $decrement = false;
119 }
120
121 } else {
122
123 // arbitrary positive value; they can proceed
124 $residual = 1;
125
126 // if it was previously ready but is no longer, refund them
127 if (
128 is_numeric($row['credits_per_rating'])
129 && is_numeric($row['max_ratings'])
130 && ($row['ready'] == 1)
131 ) {
132 // subtract a negative value
133 $amount = $row['credits_per_rating']
134 * $row['max_ratings']
135 $credits = -($amount);
136 $decrement = true;
137 }
138 }
139
140 if ($residual >= 0) {
141
142 $this->input['ip'] = $_SERVER['REMOTE_ADDR'];
143 $this->input['last_edited'] = $now;
144
145 if (! in_array(
146 $this->input['article_type'],
147 $this->article_types
148 )) {
149 $this->input['article_type'] = 1;
150 }
151
152 $result = $this->articles_gateway->updateByIdAndUserId(
153 $this->input['id'],
154 $user_id,
155 $this->input
156 );
157
158 if ($result) {
159 $article_id = $this->input['id'];
160
161 if ($decrement) {
162 $this->users_gateway->decrementCredits(
163 $user_id,
164 $credits
165 );
166 }
167 } else {
168 $this->failure[] = "Could not update article.";
169 }
170 } else {
171 $this->failure[] = "You do not have enough credits for ratings.";
172 }
173 }
174 }
175
176 public function submitNewArticle($user_id, $input)
177 {
178 $this->input = $this->filterInput($input);
179 $now = time();
180 $this->failure = array();
181 $credits = $this->getCredits();
182
183 $decrement = false;
184
185 // if the article is ready, we need to subtract credits.
186 if ($this->input['ready'] == 1) {
187
188 // if this is greater than or equal to 0, they may proceed.
189 if (
190 $credits > 0
191 && $this->input['credits_per_rating']>=0.01
192 && is_numeric($credits)
193 ) {
194 // minimum offering is 0.01
195 $residual = $user->get('credits') - $credits;
196 $decrement = true;
197 } else {
198 $residual = -1;
199 $this->failure[] = "Credit offering invalid.";
200 }
201
202 } else {
203 // arbitrary positive value if they are not done with their article.
204 // no deduction made yet.
205 $residual = 1;
206 }
207
208 // can user afford ratings on the new article?
209 if ($residual >= 0) {
210
211 // yes, insert the article
212 $this->input['last_edited'] = $now;
213 $this->input['ip'] = $_SERVER['REMOTE_ADDR'];
214 $article_id = $this->articles_gateway->insert($this->input);
215
216 if ($article_id) {
217 if ($decrement) {
218 // Charge them
219 $this->users_gateway->decrementCredits($user_id, $credits);
220 }
221 } else {
222 $this->failure[] = "Could not update credits.";
223 }
224
225 $result = $this->articles_gateway->updateByIdAndUserId(
226 $article_id,
227 $user_id,
228 $this->input
229 );
230
231 if (! $result) {
232 $this->failure[] = "Could not update article.";
233 }
234
235 } else {
236
237 // cannot afford ratings on new article
238 $this->failure[] = "You do not have enough credits for ratings.";
239 }
240 }
241 }
242 ?>
```


# 附录 E. 收集演示逻辑之前的代码

```php
**articles.php**
1 <?php
2 require "includes/setup.php";
3
4 $current_page = 'articles';
5
6 include "header.php";
7
8 $id = isset($_GET['id']) ? $_GET['id'] : 0;
9 if ($id) {
10 $page_title = "Edit An Article";
11 } else {
12 $page_title = "Submit An Article";
13 }
14
15 ?><h1><?php echo $page_title ?></h1><?php
16
17 $user_id = $user->getId();
18
19 $db = new Database($db_host, $db_user, $db_pass);
20 $articles_gateway = new ArticlesGateway($db);
21 $users_gateway = new UsersGateway($db);
22 $article_transactions = new ArticleTransactions(
23 $articles_gateway,
24 $users_gateway
25 );
26
27 if ($id) {
28 $article_transactions->updateExistingArticle($user_id, $_POST);
29 } else {
30 $article_transactions->submitNewArticle($user_id, $_POST);
31 }
32
33 $failure = $article_transactions->getFailure();
34 $input = $article_transactions->getInput();
35
36 ?>
37
38 <?php
39 if ($failure) {
40 $failure_text = implode("<br />\n", $failure);
41 echo "<h2>Failure</h2>";
42 echo "<p>We could not save the article.<br />";
43 echo $failure_text. "</p>";
44 } else {
45 echo "
46 <h2>Success</h2>
47 <p>We saved the article.</p>
48 ";
49 }
50 ?>
51
52 <form method="POST" action="<?php echo $_SERVER['PHP_SELF']?>">
53
54 <input type="hidden" name="id" value="<?php echo $id ?>" />
55
56 <h3>Title</h3>
57 <input type="text" name="title" value="<?php
58 echo $input['title']
59 ?>" size="100">
60
61
62 <h3>Article</h3>
63 <textarea name="body" cols="80" rows="30"><?php
64 echo stripslashes($input['body'])
65 ?></textarea>
66
67 <h3>Ratings</h3>
68 <p>How many rated reviews do you want?</p>
69 <select name='max_ratings'>
70 <?php for ($i = 1; $i <= 10; $i ++) {
71 echo "<option value='$i' ";
72 if ($input['max_ratings'] == $i) {
73 echo 'selected="selected"';
74 }
75 echo ">$i</option>\n";
76 } ?>
77 </select>
78
79 <p>How many credits will you give for each rating?</p>
80 <input type='text' name='credits_per_rating' value='<?php
81 echo $input['credits_per_rating'];
82 ?>' size='5' />
83
84 <h3>Notes for Reviewers</h3>
85 <input type="text" name="notes" value="<?php
86 echo $input['notes']
87 ?>" size="100">
88 <label><input type="checkbox" name="ready" <?php
89 echo $input['ready'] ? 'checked="checked"' : '';
90 ?> /> This article is ready to be rated.</label>
91
92 <p align="center">
93 <input type="submit" value="Save" name="submit">
94 </p>
95
96 </form>
97
98 <?php
99 include "footer.php";
100 ?>
```


# 附录 F. 收集演示逻辑后的代码

```php
**articles.php**
1 <?php
2 require "includes/setup.php";
3
4 $user_id = $user->getId();
5
6 $db = new Database($db_host, $db_user, $db_pass);
7 $articles_gateway = new ArticlesGateway($db);
8 $users_gateway = new UsersGateway($db);
9 $article_transactions = new ArticleTransactions(
10 $articles_gateway,
11 $users_gateway
12 );
13
14 $id = isset($_GET['id']) ? $_GET['id'] : 0;
15 if ($id) {
16 $article_transactions->updateExistingArticle($user_id, $_POST);
17 } else {
18 $article_transactions->submitNewArticle($user_id, $_POST);
19 }
20
21 $failure = $article_transactions->getFailure();
22 $input = $article_transactions->getInput();
23 $action = $_SERVER['PHP_SELF'];
24
25 /** PRESENTATION */
26
27 $current_page = 'articles';
28
29 include "header.php";
30
31 if ($id) {
32 $page_title = "Edit An Article";
33 } else {
34 $page_title = "Submit An Article";
35 }
36 ?>
37
38 <h1><?php echo $page_title ?></h1><?php
39
40 if ($failure) {
41 $failure_text = implode("<br />\n", $failure);
42 echo "<h2>Failure</h2>";
43 echo "<p>We could not save the article.<br />";
44 echo $failure_text. "</p>";
45 } else {
46 echo "
47 <h2>Success</h2>
48 <p>We saved the article.</p>
49 ";
50 }
51 ?>
52
53 <form method="POST" action="<?php echo $action ?>">
54
55 <input type="hidden" name="id" value="<?php echo $id ?>" />
56
57 <h3>Title</h3>
58 <input type="text" name="title" value="<?php
59 echo $input['title']
60 ?>" size="100">
61
62
63 <h3>Article</h3>
64 <textarea name="body" cols="80" rows="30"><?php
65 echo stripslashes($input['body'])
66 ?></textarea>
67
68 <h3>Ratings</h3>
69 <p>How many rated reviews do you want?</p>
70 <select name='max_ratings'>
71 <?php for ($i = 1; $i <= 10; $i ++) {
72 echo "<option value='$i' ";
73 if ($input['max_ratings'] == $i) {
74 echo 'selected="selected"';
75 }
76 echo ">$i</option>\n";
77 } ?>
78 </select>
79
80 <p>How many credits will you give for each rating?</p>
81 <input type='text' name='credits_per_rating' value='<?php
82 echo $input['credits_per_rating'];
83 ?>' size='5' />
84
85 <h3>Notes for Reviewers</h3>
86 <input type="text" name="notes" value="<?php
87 echo $input['notes']
88 ?>" size="100">
89 <label><input type="checkbox" name="ready" <?php
90 echo $input['ready'] ? 'checked="checked"' : '';
91 ?> /> This article is ready to be rated.</label>
92
93 <p align="center">
94 <input type="submit" value="Save" name="submit">
95 </p>
96
97 </form>
98
99 <?php
100 include "footer.php";
101 ?>
```


# 附录 G. 响应视图文件后的代码

```php
**articles.php**
1 <?php
2 require "includes/setup.php";
3
4 $user_id = $user->getId();
5
6 $db = new Database($db_host, $db_user, $db_pass);
7 $articles_gateway = new ArticlesGateway($db);
8 $users_gateway = new UsersGateway($db);
9 $article_transactions = new ArticleTransactions(
10 $articles_gateway,
11 $users_gateway
12 );
13
14 $id = isset($_GET['id']) ? $_GET['id'] : 0;
15 if ($id) {
16 $article_transactions->updateExistingArticle($user_id, $_POST);
17 } else {
18 $article_transactions->submitNewArticle($user_id, $_POST);
19 }
20
21 $response = new \Mlaphp\Response('/path/to/app/views');
22 $response->setView('articles.html.php');
23 $response->setVars(array(
24 'id' => $id,
25 'failure' => $article_transactions->getFailure(),
26 'input' => $article_transactions->getInput(),
27 'action' => $_SERVER['PHP_SELF'],
28 ));
29 $response->send();
30 ?>
**views/articles.html.php**
1 <?php
2 $current_page = 'articles';
3
4 include "header.php";
5
6 if ($id) {
7 $page_title = "Edit An Article";
8 } else {
9 $page_title = "Submit An Article";
10 }
11 ?>
12
13 <h1><?php echo $page_title ?></h1><?php
14
15 if ($failure) {
16 echo "<h2>Failure</h2>";
17 echo "<p>We could not save the article.<br />";
18 foreach ($failure as $failure_text) {
19 echo $this->esc($failure_text) . "<br />";
20 }
21 echo "</p>";
22 } else {
23 echo "
24 <h2>Success</h2>
25 <p>We saved the article.</p>
26 ";
27 }
28 ?>
29
30 <form method="POST" action="<?php echo $this->esc($action) ?>">
31
32 <input type="hidden" name="id" value="<?php echo $this->esc($id) ?>" />
33
34 <h3>Title</h3>
35 <input type="text" name="title" value="<?php
36 echo $this->esc($input['title'])
37 ?>" size="100">
38
39
40 <h3>Article</h3>
41 <textarea name="body" cols="80" rows="30"><?php
42 echo stripslashes($this->esc($input['body']))
43 ?></textarea>
44
45 <h3>Ratings</h3>
46 <p>How many rated reviews do you want?</p>
47 <select name='max_ratings'>
48 <?php for ($i = 1; $i <= 10; $i ++) {
49 $i = $this->esc($i);
50 echo "<option value='$i' ";
51 if ($input['max_ratings'] == $i) {
52 echo 'selected="selected"';
53 }
54 echo ">$i</option>\n";
55 } ?>
56 </select>
57
58 <p>How many credits will you give for each rating?</p>
59 <input type='text' name='credits_per_rating' value='<?php
60 echo $this->esc($input['credits_per_rating']);
61 ?>' size='5' />
62
63 <h3>Notes for Reviewers</h3>
64 <input type="text" name="notes" value="<?php
65 echo $this->esc($input['notes'])
66 ?>" size="100">
67 <label><input type="checkbox" name="ready" <?php
68 echo ($input['ready']) ? 'checked="checked"' : '';
69 ?> /> This article is ready to be rated.</label>
70
71 <p align="center">
72 <input type="submit" value="Save" name="submit">
73 </p>
74
75 </form>
76
77 <?php
78 include "footer.php";
79 ?>
```


# 附录 H. 控制器重新排列后的代码

```php
**articles.php**
1 <?php
2 require "includes/setup.php";
3
4 /* DEPENDENCY */
5
6 $db = new Database($db_host, $db_user, $db_pass);
7 $articles_gateway = new ArticlesGateway($db);
8 $users_gateway = new UsersGateway($db);
9 $article_transactions = new ArticleTransactions(
10 $articles_gateway,
11 $users_gateway
12 );
13 $response = new \Mlaphp\Response('/path/to/app/views');
14
15 /* CONTROLLER */
16
17 $user_id = $user->getId();
18
19 $id = isset($_GET['id']) ? $_GET['id'] : 0;
20 if ($id) {
21 $article_transactions->updateExistingArticle($user_id, $_POST);
22 } else {
23 $article_transactions->submitNewArticle($user_id, $_POST);
24 }
25
26 $response->setView('articles.html.php');
27 $response->setVars(array(
28 'id' => $id,
29 'failure' => $article_transactions->getFailure(),
30 'input' => $article_transactions->getInput(),
31 'action' => $_SERVER['PHP_SELF'],
32 ));
33
34 /* FINISHED */
35
36 $response->send();
37 ?>
```


# 附录 I. 控制器提取后的代码

```php
**articles.php**
1 <?php
2 require "includes/setup.php";
3
4 /* DEPENDENCY */
5
6 $db = new Database($db_host, $db_user, $db_pass);
7 $articles_gateway = new ArticlesGateway($db);
8 $users_gateway = new UsersGateway($db);
9 $article_transactions = new ArticleTransactions(
10 $articles_gateway,
11 $users_gateway
12 );
13 $response = new \Mlaphp\Response('/path/to/app/views');
14 $controller = new \Controller\ArticlesPage();
15
16 /* CONTROLLER */
17
18 $response = $controller->__invoke(
19 $request,
20 $response,
21 $user,
22 $article_transactions
23 );
24
25 /* FINISHED */
26
27 $response->send();
28 ?>
**classes/Controller/ArticlesPage.php**
1 <?php
2 namespace Controller;
3
4 use Domain\Articles\ArticleTransactions;
5 use Mlaphp\Request;
6 use Mlaphp\Response;
7 use User;
8
9 class ArticlesPage
10 {
11 public function __construct()
12 {
13 }
14
15 public function __invoke(
16 Request $request,
17 Response $response,
18 User $user,
19 ArticleTransactions $article_transactions
20 ) {
21 $user_id = $user->getId();
22
23 $id = isset($request->get['id'])
24 ? $request->get['id']
25 : 0;
26
27 if ($id) {
28 $article_transactions->updateExistingArticle(
29 $user_id,
30 $request->post
31 );
32 } else {
33 $article_transactions->submitNewArticle(
34 $user_id,
35 $request->post
36 );
37 }
38
39 $response->setView('articles.html.php');
40 $response->setVars(array(
41 'id' => $id,
42 'failure' => $article_transactions->getFailure(),
43 'input' => $article_transactions->getInput(),
44 'action' => $request->server['PHP_SELF'],
45 ));
46
47 return $response;
48 }
49 }
50 ?>
```


# 附录 J. 控制器依赖注入后的代码

```php
**articles.php**
1 <?php
2 require "includes/setup.php";
3
4 /* DEPENDENCY */
5
6 $db = new Database($db_host, $db_user, $db_pass);
7 $articles_gateway = new ArticlesGateway($db);
8 $users_gateway = new UsersGateway($db);
9 $article_transactions = new ArticleTransactions(
10 $articles_gateway,
11 $users_gateway
12 );
13 $response = new \Mlaphp\Response('/path/to/app/views');
14 $controller = new \Controller\ArticlesPage(
15 $request,
16 $response,
17 $user,
18 $article_transactions
19 );
20
21 /* CONTROLLER */
22
23 $response = $controller->__invoke();
24
25 /* FINISHED */
26
27 $response->send();
28 ?>
```

```php
**classes/Controller/ArticlesPage.php**
1 <?php
2 namespace Controller;
3
4 use Domain\Articles\ArticleTransactions;
5 use Mlaphp\Request;
6 use Mlaphp\Response;
7 use User;
8
9 class ArticlesPage
10 {
11 protected $user;
12
13 protected $article_transactions;
14
15 protected $request;
16
17 protected $response;
18
19 public function __construct(
20 Request $request,
21 Response $response,
22 User $user,
23 ArticleTransactions $article_transactions
24 ) {
25 $this->user = $user;
26 $this->article_transactions = $article_transactions;
27 $this->request = $request;
28 $this->response = $response;
29 }
30
31 public function __invoke()
32 {
33 $user_id = $this->user->getId();
34
35 $id = isset($this->request->get['id'])
36 ? $this->request->get['id']
37 : 0;
38
39 if ($id) {
40 $article_transactions->updateExistingArticle(
41 $user_id,
42 $this->request->post
43 );
44 } else {
Appendix J: Code After Controller Dependency Injection 217
45 $article_transactions->submitNewArticle(
46 $user_id,
47 $this->request->post
48 );
49 }
50
51 $this->response->setView('articles.html.php');
52 $this->response->setVars(array(
53 'id' => $id,
54 'failure' => $this->article_transactions->getFailure(),
55 'input' => $this->article_transactions->getInput(),
56 'action' => $this->request->server['PHP_SELF'],
57 ));
58
59 return $this->response;
60 }
61 }
62 ?>
```
