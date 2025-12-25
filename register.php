<?php
require_once 'config/database.php';
require_once 'includes/functions.php';

// ถ้าล็อกอินแล้วให้ redirect ไป dashboard
if (isLoggedIn()) {
    redirect('dashboard.php');
}

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = cleanInput($_POST['username']);
    $email = cleanInput($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $full_name = cleanInput($_POST['full_name']);
    $role = cleanInput($_POST['role']);
    
    if (empty($username)) $errors[] = 'กรุณากรอกชื่อผู้ใช้';
    elseif (strlen($username) < 4) $errors[] = 'ชื่อผู้ใช้ต้องมีอย่างน้อย 4 ตัวอักษร';

    if (empty($email)) $errors[] = 'กรุณากรอกอีเมล';
    elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'รูปแบบอีเมลไม่ถูกต้อง';

    if (empty($password)) $errors[] = 'กรุณากรอกรหัสผ่าน';
    elseif (strlen($password) < 6) $errors[] = 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร';

    if ($password !== $confirm_password) $errors[] = 'รหัสผ่านไม่ตรงกัน';

    if (empty($full_name)) $errors[] = 'กรุณากรอกชื่อ-นามสกุล';

    if (!in_array($role, ['user', 'customer', 'employee'])) $errors[] = 'กรุณาเลือกประเภทผู้ใช้';

    if (empty($errors)) {
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        if ($stmt->get_result()->num_rows > 0) $errors[] = 'ชื่อผู้ใช้นี้ถูกใช้งานแล้ว';
        $stmt->close();
    }

    if (empty($errors)) {
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        if ($stmt->get_result()->num_rows > 0) $errors[] = 'อีเมลนี้ถูกใช้งานแล้ว';
        $stmt->close();
    }

    if (empty($errors)) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $username, $email, $hashed_password, $full_name, $role);
        
        if ($stmt->execute()) {
            setAlert('สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ', 'success');
            redirect('login.php');
        } else {
            $errors[] = 'เกิดข้อผิดพลาดในการสมัครสมาชิก';
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>สมัครสมาชิก - ระบบจัดการผู้ใช้</title>
<link rel="stylesheet" href="css/style.css">

<style>
    /* โทนสีแดงเลือดหมู */
    body{
        background: linear-gradient(135deg, #7b1e3b 0%, #b11226 100%);
    }

    .card-header{
        background: linear-gradient(135deg, #7b1e3b 0%, #b11226 100%);
        color:#fff;
    }

    .btn-primary{
        background: linear-gradient(135deg, #9b2339 0%, #b11226 100%);
        color:#fff;
        border:none;
    }

    .btn-primary:hover{
        box-shadow:0 10px 20px rgba(177,18,38,.4);
        transform: translateY(-1px);
    }

    .link{
        color:#b11226;
    }

    hr{
        border-top:1px solid #e5a3ad !important;
    }

    .demo-box{
        background:#ffe5ea;
        border:1px dashed #b11226;
        color:#7b1e3b;
    }
</style>

</head>

<body>
<div class="container">
    <div class="card">
        <div class="card-header">
            <h2>📝 สมัครสมาชิก</h2>
            <p>สร้างบัญชีใหม่เพื่อเข้าใช้งานระบบ</p>
        </div>

        <div class="card-body">
            <?php if (!empty($errors)): ?>
                <div class="alert alert-error">
                    <ul style="margin:0; padding-left:20px;">
                        <?php foreach ($errors as $error): ?>
                            <li><?php echo $error; ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <form method="POST" action="">
                <div class="form-group">
                    <label>ชื่อผู้ใช้ *</label>
                    <input type="text" name="username" class="form-control"
                        value="<?php echo isset($_POST['username'])?htmlspecialchars($_POST['username']):'';?>" required>
                </div>

                <div class="form-group">
                    <label>อีเมล *</label>
                    <input type="email" name="email" class="form-control"
                        value="<?php echo isset($_POST['email'])?htmlspecialchars($_POST['email']):'';?>" required>
                </div>

                <div class="form-group">
                    <label>ชื่อ-นามสกุล *</label>
                    <input type="text" name="full_name" class="form-control"
                        value="<?php echo isset($_POST['full_name'])?htmlspecialchars($_POST['full_name']):'';?>" required>
                </div>

                <div class="form-group">
                    <label>ประเภทผู้ใช้ *</label>
                    <select name="role" class="select-control" required>
                        <option value="">-- เลือก --</option>
                        <option value="user" <?php echo (isset($_POST['role']) && $_POST['role']==='user')?'selected':''; ?>>ผู้ใช้ทั่วไป</option>
                        <option value="customer" <?php echo (isset($_POST['role']) && $_POST['role']==='customer')?'selected':''; ?>>ลูกค้า</option>
                        <option value="employee" <?php echo (isset($_POST['role']) && $_POST['role']==='employee')?'selected':''; ?>>พนักงาน</option>
                    </select>
                </div>

                <div class="form-group">
                    <label>รหัสผ่าน *</label>
                    <input type="password" name="password" class="form-control" required>
                </div>

                <div class="form-group">
                    <label>ยืนยันรหัสผ่าน *</label>
                    <input type="password" name="confirm_password" class="form-control" required>
                </div>

                <div class="form-group">
                    <button class="btn btn-primary" type="submit">สมัครสมาชิก</button>
                </div>

                <div class="text-center">
                    <p>มีบัญชีอยู่แล้ว? <a href="index.php" class="link">เข้าสู่ระบบ</a></p>
                </div>
            </form>
        </div>
    </div>
</div>
</body>
</html>
