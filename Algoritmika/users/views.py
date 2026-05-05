from django.shortcuts import render, redirect
from django.db import connection
from django.db.utils import DatabaseError
from django.views.decorators.csrf import csrf_protect
import hashlib
from datetime import date

def check_password(plain_password, stored_password):
    """Проверка пароля"""
    # MD5
    if hashlib.md5(plain_password.encode('utf-8')).hexdigest() == stored_password:
        return True
    # SHA256
    if hashlib.sha256(plain_password.encode('utf-8')).hexdigest() == stored_password:
        return True
    # Plain text
    if plain_password == stored_password:
        return True
    return False

def login_required(view_func):
    """Декоратор для проверки входа"""
    def wrapper(request, *args, **kwargs):
        if not request.session.get('is_logged_in'):
            return redirect('index')

        request.user_data = request.session.get('user', {})
        return view_func(request, *args, **kwargs)
    return wrapper


def index(request):
    return render(request, 'index.html')

def _fetchone_dict(cursor):
    row = cursor.fetchone()
    if not row:
        return None
    columns = [col[0] for col in cursor.description]
    return dict(zip(columns, row))

def _fetchall_dicts(cursor):
    rows = cursor.fetchall()
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in rows]

# --- Логин для учеников (таблица dbo.student) ---
@csrf_protect
def student_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        with connection.cursor() as cursor:
            # Указываем только те поля, которые есть в таблице
            cursor.execute("""
                SELECT id_student, first_name, last_name, 
                       ISNULL(middle_name, '') as middle_name,
                       ISNULL(phone, '') as phone,
                       password
                FROM dbo.student
                WHERE username = %s
            """, [username])
            
            row = cursor.fetchone()
            
            # Проверяем пароль (password на позиции 5)
            if row and check_password(password, row[5]):
                request.session['is_logged_in'] = True
                request.session['user'] = {
                    'id': row[0],
                    'username': username,
                    'first_name': row[1],
                    'last_name': row[2],
                    'middle_name': row[3],
                    'phone': row[4],
                    'role': 'student',
                }
                request.session.set_expiry(5400)
                return redirect('student_dashboard')
            else:
                return render(request, 'login_student.html', {
                    'error': 'Неверный логин или пароль ученика'
                })
    
    return render(request, 'login_student.html')

# --- Логин для родителей (таблица dbo.parent) ---
# Аналогично, но с учетом структуры таблицы parent
@csrf_protect
def parent_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        with connection.cursor() as cursor:
            # Проверяем структуру таблицы parent
            cursor.execute("""
                SELECT id_parent, first_name, last_name, 
                       ISNULL(middle_name, '') as middle_name,
                       ISNULL(phone, '') as phone,
                       ISNULL(email, '') as email,
                       password
                FROM dbo.parent
                WHERE username = %s
            """, [username])
            
            row = cursor.fetchone()
            
            # Если нет поля email, используйте запрос без него
            if not row:
                cursor.execute("""
                    SELECT id_parent, first_name, last_name, 
                           ISNULL(middle_name, '') as middle_name,
                           ISNULL(phone, '') as phone,
                           password
                    FROM dbo.parent
                    WHERE username = %s
                """, [username])
                row = cursor.fetchone()
                if row and check_password(password, row[5]):
                    request.session['is_logged_in'] = True
                    request.session['user'] = {
                        'id': row[0],
                        'username': username,
                        'first_name': row[1],
                        'last_name': row[2],
                        'middle_name': row[3],
                        'phone': row[4],
                        'role': 'parent',
                    }
                    request.session.set_expiry(5400)
                    return redirect('parent_dashboard')
            elif row and check_password(password, row[6]):  # если есть email
                request.session['is_logged_in'] = True
                request.session['user'] = {
                    'id': row[0],
                    'username': username,
                    'first_name': row[1],
                    'last_name': row[2],
                    'middle_name': row[3],
                    'phone': row[4],
                    'email': row[5],
                    'role': 'parent',
                }
                request.session.set_expiry(5400)
                return redirect('parent_dashboard')
            else:
                return render(request, 'login_parent.html', {
                    'error': 'Неверный логин или пароль родителя'
                })
    
    return render(request, 'login_parent.html')

# --- Логин для сотрудников ---
@csrf_protect
def employee_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Здесь нужно узнать структуру таблицы для сотрудников
        # Пока сделаем заглушку
        with connection.cursor() as cursor:
            # Проверяем таблицу position (если там есть логины)
            try:
                cursor.execute("""
                    SELECT id, first_name, last_name, 
                           ISNULL(middle_name, '') as middle_name,
                           ISNULL(phone, '') as phone,
                           password
                    FROM dbo.position
                    WHERE username = %s
                """, [username])
                row = cursor.fetchone()
                
                if row and check_password(password, row[5]):
                    request.session['is_logged_in'] = True
                    request.session['user'] = {
                        'id': row[0],
                        'username': username,
                        'first_name': row[1],
                        'last_name': row[2],
                        'middle_name': row[3],
                        'phone': row[4],
                        'role': 'employee',
                    }
                    request.session.set_expiry(5400)
                    return redirect('employee_dashboard')
            except:
                pass
            
            return render(request, 'login_employee.html', {
                'error': 'Неверный логин или пароль сотрудника'
            })
    
    return render(request, 'login_employee.html')

# --- Выход ---
def logout_view(request):
    request.session.flush()
    return redirect('index')

# --- Дашборды ---
@login_required
def student_dashboard(request):
    if request.user_data.get('role') != 'student':
        return redirect('student_login')

    student_id = request.user_data.get('id')
    if not student_id:
        return redirect('student_login')

    context = {
        'title': 'Личный кабинет ученика',
        'user': request.user_data,
        'today': date.today(),
        'student': None,
        'enrollment': None,
        'group': None,
        'course': None,
        'upcoming_classes': [],
        'weekly_schedule': [],
        'progress': {
            'lessons_total': 0,
            'assignments_total': 0,
            'assignments_done': 0,
            'assignments_done_percent': 0,
            'attendance_total': 0,
            'attendance_breakdown': [],
        },
        'db_warning': None,
    }

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    id_student,
                    username,
                    first_name,
                    last_name,
                    ISNULL(middle_name, '') AS middle_name,
                    ISNULL(phone, '') AS phone,
                    ISNULL(CONVERT(varchar(10), birth_date, 120), '') AS birth_date,
                    ISNULL(gender, '') AS gender,
                    ISNULL(CONVERT(varchar(10), admission_date, 120), '') AS admission_date
                FROM dbo.student
                WHERE id_student = %s
            """, [student_id])
            context['student'] = _fetchone_dict(cursor)

            cursor.execute("""
                SELECT TOP 1
                    id_enrollment,
                    id_student,
                    id_group_name,
                    enrollment_date
                FROM dbo.enrollment
                WHERE id_student = %s
                ORDER BY enrollment_date DESC
            """, [student_id])
            context['enrollment'] = _fetchone_dict(cursor)

            group_name = context['enrollment']['id_group_name'] if context['enrollment'] else None
            if group_name:
                cursor.execute("""
                    SELECT
                        cg.id_group_name,
                        cg.week_day,
                        cg.class_time,
                        cg.frequency,
                        cg.max_students,
                        cg.id_course,
                        cg.id_room_number,
                        cg.id_branch_name,
                        ISNULL(b.address, '') AS branch_address,
                        ISNULL(b.work_schedule, '') AS branch_work_schedule,
                        ISNULL(cr.capacity, 0) AS room_capacity
                    FROM dbo.class_group cg
                    LEFT JOIN dbo.branch b ON b.id_branch_name = cg.id_branch_name
                    LEFT JOIN dbo.classroom cr ON cr.id_room_number = cg.id_room_number
                    WHERE cg.id_group_name = %s
                """, [group_name])
                context['group'] = _fetchone_dict(cursor)

                course_id = context['group']['id_course'] if context['group'] else None
                if course_id:
                    cursor.execute("""
                        SELECT
                            c.id_course,
                            c.title,
                            ISNULL(c.description, '') AS description,
                            ISNULL(c.age_group, '') AS age_group,
                            ISNULL(c.difficulty, '') AS difficulty,
                            ISNULL(cs.status_name, '') AS status_name
                        FROM dbo.course c
                        LEFT JOIN dbo.course_status cs ON cs.id_course_status = c.id_course_status
                        WHERE c.id_course = %s
                    """, [course_id])
                    context['course'] = _fetchone_dict(cursor)

                    cursor.execute("""
                        SELECT COUNT(*) AS lessons_total
                        FROM dbo.lesson l
                        INNER JOIN dbo.module m ON m.id_module = l.id_module
                        WHERE m.id_course = %s
                    """, [course_id])
                    lessons_total_row = _fetchone_dict(cursor) or {'lessons_total': 0}
                    context['progress']['lessons_total'] = int(lessons_total_row.get('lessons_total') or 0)

                    cursor.execute("""
                        SELECT COUNT(*) AS assignments_total
                        FROM dbo.assignment a
                        INNER JOIN dbo.lesson l ON l.id_lesson = a.id_lesson
                        INNER JOIN dbo.module m ON m.id_module = l.id_module
                        WHERE m.id_course = %s
                    """, [course_id])
                    assignments_total_row = _fetchone_dict(cursor) or {'assignments_total': 0}
                    context['progress']['assignments_total'] = int(assignments_total_row.get('assignments_total') or 0)

                    cursor.execute("""
                        SELECT COUNT(DISTINCT ar.id_assignment) AS assignments_done
                        FROM dbo.assignment_result ar
                        INNER JOIN dbo.assignment a ON a.id_assignment = ar.id_assignment
                        INNER JOIN dbo.lesson l ON l.id_lesson = a.id_lesson
                        INNER JOIN dbo.module m ON m.id_module = l.id_module
                        WHERE ar.id_student = %s AND m.id_course = %s
                    """, [student_id, course_id])
                    assignments_done_row = _fetchone_dict(cursor) or {'assignments_done': 0}
                    context['progress']['assignments_done'] = int(assignments_done_row.get('assignments_done') or 0)

                    total = context['progress']['assignments_total']
                    done = context['progress']['assignments_done']
                    context['progress']['assignments_done_percent'] = int((done / total) * 100) if total else 0

                cursor.execute("""
                    SELECT TOP 12
                        cl.class_date,
                        cl.class_time,
                        c.id_course,
                        ISNULL(c.title, '') AS course_title,
                        ISNULL(b.address, '') AS branch_address,
                        cg.id_room_number
                    FROM dbo.class cl
                    INNER JOIN dbo.class_group cg ON cg.id_group_name = cl.id_group_name
                    LEFT JOIN dbo.course c ON c.id_course = cg.id_course
                    LEFT JOIN dbo.branch b ON b.id_branch_name = cg.id_branch_name
                    WHERE cl.id_group_name = %s AND cl.class_date >= CAST(GETDATE() AS date)
                    ORDER BY cl.class_date ASC, cl.class_time ASC
                """, [group_name])
                context['upcoming_classes'] = _fetchall_dicts(cursor)

                cursor.execute("""
                    SELECT
                        cg.week_day,
                        cg.class_time,
                        cg.frequency,
                        c.id_course,
                        ISNULL(c.title, '') AS course_title,
                        cg.id_room_number,
                        ISNULL(b.address, '') AS branch_address
                    FROM dbo.class_group cg
                    LEFT JOIN dbo.course c ON c.id_course = cg.id_course
                    LEFT JOIN dbo.branch b ON b.id_branch_name = cg.id_branch_name
                    WHERE cg.id_group_name = %s
                """, [group_name])
                context['weekly_schedule'] = _fetchall_dicts(cursor)

                cursor.execute("""
                    SELECT
                        ISNULL(ats.status_name, 'unknown') AS status_name,
                        COUNT(*) AS cnt
                    FROM dbo.attendance a
                    LEFT JOIN dbo.attendance_status ats ON ats.id_attendance_status = a.id_attendance_status
                    INNER JOIN dbo.class cl ON cl.id_class = a.id_class
                    WHERE a.id_student = %s AND cl.id_group_name = %s
                    GROUP BY ats.status_name
                    ORDER BY cnt DESC
                """, [student_id, group_name])
                breakdown = _fetchall_dicts(cursor)
                context['progress']['attendance_breakdown'] = breakdown
                context['progress']['attendance_total'] = int(sum(int(x.get('cnt') or 0) for x in breakdown))

    except DatabaseError as e:
        context['db_warning'] = f'Ошибка чтения данных из MSSQL: {e}'

    return render(request, 'student_dashboard.html', context)


@login_required
def course_detail(request, course_id: int):
    if request.user_data.get('role') != 'student':
        return redirect('index')

    student_id = request.user_data.get('id')
    if not student_id:
        return redirect('student_login')

    context = {
        'title': 'Курс',
        'user': request.user_data,
        'course': None,
        'modules': [],
        'progress': {
            'lessons_total': 0,
            'assignments_total': 0,
            'assignments_done': 0,
            'assignments_done_percent': 0,
        },
        'db_warning': None,
    }

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    c.id_course,
                    c.title,
                    ISNULL(c.description, '') AS description,
                    ISNULL(c.age_group, '') AS age_group,
                    ISNULL(c.difficulty, '') AS difficulty,
                    ISNULL(cs.status_name, '') AS status_name
                FROM dbo.course c
                LEFT JOIN dbo.course_status cs ON cs.id_course_status = c.id_course_status
                WHERE c.id_course = %s
            """, [course_id])
            context['course'] = _fetchone_dict(cursor)

            if not context['course']:
                return render(request, 'course_detail.html', context)

            cursor.execute("""
                SELECT
                    m.id_module,
                    m.title,
                    ISNULL(m.goal, '') AS goal,
                    ISNULL(m.is_Elective, 0) AS is_elective
                FROM dbo.module m
                WHERE m.id_course = %s
                ORDER BY m.id_module ASC
            """, [course_id])
            modules = _fetchall_dicts(cursor)

            cursor.execute("""
                SELECT
                    l.id_lesson,
                    l.id_module,
                    l.title,
                    ISNULL(l.description, '') AS description,
                    ISNULL(l.homework, '') AS homework
                FROM dbo.lesson l
                INNER JOIN dbo.module m ON m.id_module = l.id_module
                WHERE m.id_course = %s
                ORDER BY l.id_module ASC, l.id_lesson ASC
            """, [course_id])
            lessons = _fetchall_dicts(cursor)

            cursor.execute("""
                SELECT
                    a.id_assignment,
                    a.id_lesson,
                    a.title,
                    ISNULL(a.description, '') AS description
                FROM dbo.assignment a
                INNER JOIN dbo.lesson l ON l.id_lesson = a.id_lesson
                INNER JOIN dbo.module m ON m.id_module = l.id_module
                WHERE m.id_course = %s
                ORDER BY a.id_lesson ASC, a.id_assignment ASC
            """, [course_id])
            assignments = _fetchall_dicts(cursor)

            cursor.execute("""
                SELECT DISTINCT ar.id_assignment
                FROM dbo.assignment_result ar
                INNER JOIN dbo.assignment a ON a.id_assignment = ar.id_assignment
                INNER JOIN dbo.lesson l ON l.id_lesson = a.id_lesson
                INNER JOIN dbo.module m ON m.id_module = l.id_module
                WHERE ar.id_student = %s AND m.id_course = %s
            """, [student_id, course_id])
            done_ids = {row[0] for row in cursor.fetchall()}

            lesson_map = {}
            for l in lessons:
                l['assignments'] = []
                l['assignments_total'] = 0
                l['assignments_done'] = 0
                lesson_map[l['id_lesson']] = l

            for a in assignments:
                a['is_done'] = a['id_assignment'] in done_ids
                l = lesson_map.get(a['id_lesson'])
                if l is not None:
                    l['assignments'].append(a)
                    l['assignments_total'] += 1
                    if a['is_done']:
                        l['assignments_done'] += 1

            lessons_by_module = {}
            for l in lessons:
                lessons_by_module.setdefault(l['id_module'], []).append(l)

            for m in modules:
                m_lessons = lessons_by_module.get(m['id_module'], [])
                m['lessons'] = m_lessons
                m['lessons_total'] = len(m_lessons)
                m['assignments_total'] = sum(int(x.get('assignments_total') or 0) for x in m_lessons)
                m['assignments_done'] = sum(int(x.get('assignments_done') or 0) for x in m_lessons)
                context['modules'].append(m)

            cursor.execute("""
                SELECT COUNT(*) AS lessons_total
                FROM dbo.lesson l
                INNER JOIN dbo.module m ON m.id_module = l.id_module
                WHERE m.id_course = %s
            """, [course_id])
            context['progress']['lessons_total'] = int((_fetchone_dict(cursor) or {}).get('lessons_total') or 0)

            cursor.execute("""
                SELECT COUNT(*) AS assignments_total
                FROM dbo.assignment a
                INNER JOIN dbo.lesson l ON l.id_lesson = a.id_lesson
                INNER JOIN dbo.module m ON m.id_module = l.id_module
                WHERE m.id_course = %s
            """, [course_id])
            context['progress']['assignments_total'] = int((_fetchone_dict(cursor) or {}).get('assignments_total') or 0)

            context['progress']['assignments_done'] = len(done_ids)
            total = context['progress']['assignments_total']
            done = context['progress']['assignments_done']
            context['progress']['assignments_done_percent'] = int((done / total) * 100) if total else 0

    except DatabaseError as e:
        context['db_warning'] = f'Ошибка чтения данных из MSSQL: {e}'

    context['title'] = context['course']['title'] if context['course'] and context['course'].get('title') else 'Курс'
    return render(request, 'course_detail.html', context)

@login_required
def parent_dashboard(request):
    if request.user_data.get('role') != 'parent':
        return redirect('parent_login')
    
    return render(request, 'dashboard.html', {
        'user': request.user_data,
        'title': 'Родительский контроль'
    })

@login_required
def employee_dashboard(request):
    if request.user_data.get('role') != 'employee':
        return redirect('employee_login')
    
    return render(request, 'dashboard.html', {
        'user': request.user_data,
        'title': 'Рабочая область сотрудника'
    })