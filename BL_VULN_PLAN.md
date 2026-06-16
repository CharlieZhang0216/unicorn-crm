# 业务逻辑漏洞实现计划 v2
# 创建时间: 2026-06-16 22:54
#
# 设计原则（用户要求）：
# 1. 不做提示、不标记、看似完全正常的业务功能
# 2. 每个漏洞需要理解业务流程才能发现和利用
# 3. 不需要代码审计就能在 UI 中触达

## 实现清单

### BL-1: Customer Dedup 归属劫持
- 文件: routes/customers-batch.js (重写)
- 入口: /customers 页面 → "Find Duplicates" 按钮 → 合并操作
- 漏洞: 合并客户时，先 delete 旧记录再 insert 新记录的非原子操作
- 触发: 2个 admin 同时合并同一组客户，或合并在 create 间隙
- 表现: 客户数据归属错乱

### BL-2: Tier auto-upgrade 时序
- 文件: services/scheduler.js (添加 tier_upgrade job)
- 入口: 不可见（系统自动运行），但 Orders 页面显示 total 金额
- 漏洞: 凌晨 2:00 自动扫描 orders 表计算客户总采购额，含未支付/已取消订单
- 触发: 创建大额订单 → 升级 → 取消订单 → 保留高级 tier

### BL-3: Export 列注入  
- 文件: routes/export.js (修改 customers export)
- 入口: /customers → Export 按钮 → 前端传 columns 参数
- 漏洞: CSV 导出按客户端 columns 参数动态拼 SQL，无白名单校验
- 触发: 拦截导出请求，修改 columns 参数注入子查询

### BL-4: Ticket SLA 关键词升级
- 文件: routes/tickets.js (修改 POST comment)
- 入口: /tickets → 打开 ticket → 添加 comment
- 漏洞: 扫描 comment 内容中的关键词自动升级 priority
- 触发: 在评论中使用 "urgent"/"数据泄露"/"outage" 等词

### BL-5: Order 审批并发覆盖
- 文件: routes/orders.js (修改 approve 逻辑)
- 入口: /orders → 打开订单 → 两个 manager 同时点 Approve
- 漏洞: approval_step 更新用乐观读-改-写，无锁
- 触发: A 读 step=0 → B 读 step=0 → A 写 step=1 → B 写 step=1（覆盖）
