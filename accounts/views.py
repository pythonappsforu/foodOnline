import datetime

from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.shortcuts import render,redirect
from django.template.defaultfilters import slugify
from django.utils.http import urlsafe_base64_decode

from orders.models import Order
from vendor.forms import VendorForm
from vendor.models import Vendor
from .models import User, UserProfile
from accounts.forms import UserForm
from django.contrib import messages, auth
from .utils import detectUser, send_verification_email


# Create your views here.

# restrict vendor from accessing customer pages
def check_role_vendor(user):
    if user.role == 1:
        return True
    else:
        raise PermissionDenied
def check_role_customer(user):
    if user.role == 2:
        return True
    else:
        raise PermissionDenied

def registerUser(request):
    if request.user.is_authenticated:
        messages.warning(request,'you are already logged in')
        return redirect('myAccount')
    elif request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            # Create the user using the form
            # password = form.cleaned_data['password']
            # user = form.save(commit=False)
            # user.set_password(password)
            # user.role = User.CUSTOMER
            # user.save()

            # Create the user using create_user method
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name,
                                            last_name=last_name,
                                            username=username, email=email,
                                            password=password)
            user.role = User.CUSTOMER
            user.save()

            #send verification email
            mail_subject = 'Please activate your account'
            email_template = 'accounts/emails/account_verification_email.html'
            send_verification_email(request, user, mail_subject,
                                    email_template)

            messages.success(request,'Your account has been registered sucessfully!')
            return redirect('registerUser')

        else:
            print(form.errors)
    else:
        form = UserForm()
    context ={
        'form':form,
    }
    return render(request,'accounts/registerUser.html',context)


def registerVendor(request):
    if request.user.is_authenticated:
        messages.warning(request,'you are already logged in')
        return redirect('myAccount')
    elif request.method == 'POST':
        form = UserForm(request.POST)
        vendor_form = VendorForm(request.POST,request.FILES)

        if form.is_valid() and vendor_form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name,
                                            last_name=last_name,
                                            username=username, email=email,
                                            password=password)
            user.role = User.VENDOR
            user.save()
            vendor = vendor_form.save(commit=False)
            vendor.user = user
            vendor_name = vendor_form.cleaned_data['vendor_name']
            vendor.vendor_slug = slugify(vendor_name) + '-' + str(user.id)
            user_profile = UserProfile.objects.get(user=user)
            vendor.user_profile = user_profile
            vendor.save()

            # send verification email
            mail_subject = 'please activate your account'
            email_template = 'accounts/emails/account_verification_email.html'
            send_verification_email(request, user, mail_subject,
                                    email_template)

            messages.success(request,'Your account has been registered sucessfully! Please wait for the approval.')
            return redirect('registerVendor')

        else:
            print("invalid vendor form")
            print(form.errors)

    else:
        form = UserForm()
        vendor_form = VendorForm()
    context = {
        'form': form,
        'vendor_form': vendor_form,
    }
    return render(request,'accounts/registerVendor.html',context)


def activate(request, uidb64, token):
    # activate the user by setting is_active status to True
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(ValueError,TypeError,OverflowError,User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request,'Congratulations! Your account has been activated sucessfully!')
        return redirect('myAccount')
    else:
        messages.error(request,'Activation link is invalid!')
        return redirect('login')


def login(request):
    if request.user.is_authenticated:
        messages.warning(request,'you are already logged in')
        return redirect('myAccount')
    elif request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)

        if user is not None:
            auth.login(request, user)
            messages.success(request,'You are logged in successfully')
            return redirect('myAccount')
        else:
            messages.error(request,'Invalid username or password')
            return redirect('login')

    return render(request,'accounts/login.html')


def logout(request):
    auth.logout(request)
    messages.info(request,'you have been logged out')
    return redirect('login')


@login_required(login_url='login')
def myAccount(request):
    user = request.user
    redirectUrl = detectUser(user)
    return redirect(redirectUrl)


@login_required(login_url='login')
@user_passes_test(check_role_customer)
def custDashboard(request):
    orders = Order.objects.filter(user=request.user,is_ordered=True)
    recent_orders = orders[:5]
    context = {
        'orders':orders,
        'orders_count':orders.count,
        'recent_orders':recent_orders,
    }
    return render(request,'accounts/custDashboard.html',context)


@login_required(login_url='login')
@user_passes_test(check_role_vendor)
def vendorDashboard(request):
    vendor = Vendor.objects.get(user=request.user)
    orders = Order.objects.filter(vendors__in=[vendor.id],
                                  is_ordered=True).order_by('created_at')
    recent_orders = orders[:10]

    # current month's revenue
    current_month = datetime.datetime.now().month
    current_month_orders = orders.filter(vendors__in=[vendor.id],
                                         created_at__month=current_month)
    current_month_revenue = 0
    for i in current_month_orders:
        current_month_revenue += i.get_total_by_vendor()['grand_total']

    # total revenue
    total_revenue = 0
    for i in orders:
        total_revenue += i.get_total_by_vendor()['grand_total']
    context = {
        'orders': orders,
        'orders_count': orders.count(),
        'recent_orders': recent_orders,
        'total_revenue': total_revenue,
        'current_month_revenue': current_month_revenue,
    }
    return render(request, 'accounts/vendorDashboard.html', context)

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email__exact=email)

            # send password reset email
            mail_subject = 'Password reset'
            email_template = 'accounts/emails/password_reset_email.html'
            send_verification_email(request,user,mail_subject,email_template)
            messages.success(request,'Please check your email to reset your password')
            return redirect('login')
        else:
            messages.error(request,'Account does not exist')
            return redirect('forgot_password')

    return render(request,'accounts/forgot_password.html')

def reset_password_validate(request,uidb64,token):
    #validate user by decoding token and pk
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(ValueError, TypeError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.info(request,'please reset your password')
        return redirect('reset_password')
    else:
        messages.error(request,'Activation link is invalid!')
        return redirect('login')

def reset_password(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            pk = request.session.get('uid')
            user = User.objects.get(pk=pk)
            user.set_password(password)
            user.is_active = True
            user.save()
            messages.success(request,'Password reset successful')
            return redirect('login')

        else:
            messages.error(request,'Passwords do not match')
            return redirect('reset_password')

    return render(request,'accounts/reset_password.html')