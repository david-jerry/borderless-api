from django.shortcuts import redirect, render

def redirect_home_view(request):
    if request.user.is_authenticated:
        return redirect("/api/v1/docs/")
    return redirect("admin:index")
