# apps/accounts/email_templates.py

EMAIL_VERIFICATION_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>تأكيد البريد الإلكتروني</title>
<style>
body{
margin:0;
padding:0;
background:#f5f7fb;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
.wrapper{
width:100%;
padding:40px 10px;
}
.container{
max-width:540px;
margin:auto;
background:#ffffff;
border-radius:12px;
box-shadow:0 8px 30px rgba(0,0,0,0.05);
overflow:hidden;
}
.header{
background:linear-gradient(135deg,#2563eb,#1e40af);
padding:35px;
text-align:center;
color:white;
}
.logo{
font-size:26px;
font-weight:700;
letter-spacing:1px;
}
.subtitle{
font-size:14px;
opacity:0.9;
margin-top:5px;
}
.content{
padding:35px;
text-align:center;
color:#374151;
font-size:15px;
line-height:1.8;
}
.otp{
margin:35px auto;
font-size:38px;
font-weight:700;
letter-spacing:10px;
background:#f3f4f6;
padding:18px 30px;
display:inline-block;
border-radius:10px;
color:#111827;
}
.note{
font-size:14px;
color:#6b7280;
margin-top:15px;
}
.security{
margin-top:25px;
font-size:13px;
color:#9ca3af;
}
.footer{
margin-top:30px;
padding:25px;
text-align:center;
font-size:12px;
color:#9ca3af;
background:#fafafa;
}
</style>
</head>
<body>
<div class="wrapper">
<div class="container">
<div class="header">
<div class="logo">SafeClick</div>
<div class="subtitle">Secure Account Verification</div>
</div>
<div class="content">
مرحباً،
<br><br>
شكراً لإنشاء حساب في <b>SafeClick</b>.
<br>
يرجى استخدام رمز التحقق التالي لتأكيد بريدك الإلكتروني وإكمال إنشاء الحساب.
<div class="otp">
{{OTP_CODE}}
</div>
<div class="note">
هذا الرمز صالح لمدة <b>5 دقائق</b> فقط.
</div>
<div class="security">
إذا لم تقم بإنشاء حساب في SafeClick يمكنك تجاهل هذه الرسالة.
</div>
</div>
<div class="footer">
© 2026 SafeClick Security Platform <br>
هذه رسالة تلقائية من نظام الأمان، يرجى عدم الرد عليها.
</div>
</div>
</div>
</body>
</html>
"""

PASSWORD_RESET_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>استعادة كلمة المرور</title>
<style>
body{
margin:0;
padding:0;
background:#f5f7fb;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
.wrapper{
width:100%;
padding:40px 10px;
}
.container{
max-width:540px;
margin:auto;
background:#ffffff;
border-radius:12px;
box-shadow:0 8px 30px rgba(0,0,0,0.05);
overflow:hidden;
}
.header{
background:linear-gradient(135deg,#ef4444,#b91c1c);
padding:35px;
text-align:center;
color:white;
}
.logo{
font-size:26px;
font-weight:700;
letter-spacing:1px;
}
.subtitle{
font-size:14px;
opacity:0.9;
margin-top:5px;
}
.content{
padding:35px;
text-align:center;
color:#374151;
font-size:15px;
line-height:1.8;
}
.otp{
margin:35px auto;
font-size:38px;
font-weight:700;
letter-spacing:10px;
background:#f3f4f6;
padding:18px 30px;
display:inline-block;
border-radius:10px;
color:#111827;
}
.note{
font-size:14px;
color:#6b7280;
margin-top:15px;
}
.warning{
margin-top:20px;
font-size:13px;
color:#ef4444;
}
.footer{
margin-top:30px;
padding:25px;
text-align:center;
font-size:12px;
color:#9ca3af;
background:#fafafa;
}
</style>
</head>
<body>
<div class="wrapper">
<div class="container">
<div class="header">
<div class="logo">SafeClick</div>
<div class="subtitle">Password Reset Request</div>
</div>
<div class="content">
مرحباً،
<br><br>
تلقينا طلباً لإعادة تعيين كلمة المرور الخاصة بحسابك في <b>SafeClick</b>.
<br>
استخدم رمز التحقق التالي لإكمال عملية تغيير كلمة المرور.
<div class="otp">
{{OTP_CODE}}
</div>
<div class="note">
ينتهي هذا الرمز خلال <b>5 دقائق</b>.
</div>
<div class="warning">
إذا لم تقم بطلب إعادة تعيين كلمة المرور، يرجى تجاهل هذه الرسالة فوراً.
</div>
</div>
<div class="footer">
© 2026 SafeClick Security Platform <br>
هذه رسالة أمان تلقائية من نظام SafeClick.
</div>
</div>
</div>
</body>
</html>
"""
