from django import forms

class SignupForm(forms.Form):
    username = forms.CharField(label='username', max_length=100)
    balance = forms.DecimalField(label='balance', max_digits=10, decimal_places=2)
    password = forms.CharField(label='password', max_length=100, widget=forms.PasswordInput)