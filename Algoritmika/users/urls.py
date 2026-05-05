# users/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('login/student/', views.student_login, name='student_login'),
    path('login/parent/', views.parent_login, name='parent_login'),
    path('login/employee/', views.employee_login, name='employee_login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/student/', views.student_dashboard, name='student_dashboard'),
    path('dashboard/parent/', views.parent_dashboard, name='parent_dashboard'),
    path('dashboard/employee/', views.employee_dashboard, name='employee_dashboard'),
    path('course/<int:course_id>/', views.course_detail, name='course_detail'),
]