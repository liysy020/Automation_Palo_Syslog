from django import forms

class login_form (forms.Form):
	username_form_textinput = forms.CharField(label="Username", widget=forms.TextInput(attrs={'size': '10'}))
	password_form_password = forms.CharField(label ='Password', widget=forms.PasswordInput)