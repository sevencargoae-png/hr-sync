# HR Sync Server — منصة شؤون الموظفين (SEVENGATES)
خادم مزامنة مركزي بتشفير طرف-لطرف. يخزّن قاعدة بيانات الشركة مشفّرة (blob) ولا يرى محتواها.

متغيرات البيئة المطلوبة: DATABASE_URL, COMPANY_TOKEN, PORT (افتراضي 3000)

نقاط النهاية: GET /healthz · GET /sync/pull · POST /sync/push · POST /sync/meta (كلها تتطلب Authorization: Bearer COMPANY_TOKEN عدا healthz)
