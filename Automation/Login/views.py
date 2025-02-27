from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .forms import login_form
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages

def login_request(request):
	if request.method == 'POST':
		form = login_form(request.POST)
		if form.is_valid():
			name = form.cleaned_data['username_form_textinput']
			pwd = form.cleaned_data['password_form_password']
			valuenext= request.POST.get('next')
			try:
				user= authenticate(username=name, password=pwd)
			except:
				content = {'form': form, 'error':'The username and password is incorrect'}
				return render(request, 'login.html', content)
			if user is not None and valuenext=='':
				login(request, user)
				return redirect ('/')
			elif user is not None and valuenext !='':
				login(request, user)
				messages.success(request, "You have successfully logged in")
				return redirect(valuenext)
			return render(request,'login.html', {'form': form, 'error':'The username and password is incorrect'})
	else:
		content= {'form': login_form ()}
		return render (request, 'login.html',content)
def logout_request(request):
	logout (request)
	return redirect('/')