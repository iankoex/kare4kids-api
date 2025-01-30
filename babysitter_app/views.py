from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.paginator import Paginator
from django.views.generic.edit import FormView
from .models import Sitter, Parent
from .forms import UserRegistrationForm, LoginForm, SitterForm, ParentForm
from .serializers import SitterSerializer, UserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.generic.edit import CreateView, UpdateView
from django.urls import reverse_lazy
from .models import Parent
from .forms import ParentForm
from django.views.generic.edit import DeleteView
from django.urls import reverse_lazy


def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)       
        if form.is_valid():
            user = form.save()
            messages.success(request, "Your account has been created! You can now log in.")
            return redirect('login')
    else:
        form = UserRegistrationForm()

    return render(request, 'registration/register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')  # Replace 'home' with your desired redirect URL name
            else:
                form.add_error(None, "Invalid username or password.")
    else:
        form = LoginForm()

    return render(request, 'registration/login.html', {'form': form})

@login_required
def user_logout(request):
    logout(request)
    return redirect('home')

class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

# API for JWT Login (Sign-In)
class LoginAPIView(APIView):
    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(request, username=username, password=password)
        # Authenticate user
        if user:
           # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            return Response({
                'refresh': str(refresh),
                'access': str(access_token),
            }, status=status.HTTP_200_OK)

        return Response({
            'detail': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)

def home(request):
    sitters = Sitter.objects.all()
    return render (request, 'babysitter_app/home.html', {'sitters': sitters})

class CreateSitterView(FormView):
    template_name = 'babysitter_app/create_update_sitter.html'
    form_class = SitterForm

    def form_valid(self, form):
        form.save()  # Save the new sitter
        return redirect('sitter_list')  # Redirect to the sitter list view

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))

class UpdateSitterView(FormView):
    template_name = 'babysitter_app/create_update_sitter.html'
    form_class = SitterForm

    def get_object(self):
        pk = self.kwargs.get('pk')
        return get_object_or_404(Sitter, pk=pk)

    def get_initial(self):
        initial = super().get_initial()
        sitter = self.get_object()
        initial.update({
            'name': sitter.name,
            'bio': sitter.bio,
            'hourly_rate': sitter.hourly_rate,
            'location': sitter.location
        })
        return initial

    def form_valid(self, form):
        form.save()  # Save the updated sitter
        return redirect('sitter_list')  # Redirect to the sitter list view

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))

def sitter_list(request):
    sitters = Sitter.objects.all().order_by('name')  
    paginator = Paginator(sitters, 10)

    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'babysitter_app/sitter_list.html', {'page_obj': page_obj})

def sitter_detail(request, sitter_id):
    sitter = get_object_or_404(Sitter, id=sitter_id)  # Get the sitter by ID or return a 404
    return render(request, 'babysitter_app/sitter_detail.html', {'sitter': sitter})

def delete_sitter(request, pk):  
    sitter = get_object_or_404(Sitter, pk=pk)

    if request.method == 'POST':
        sitter.delete()
        return redirect('sitter_list')

    return render(request, 'babysitter_app/delete_sitter.html', {'sitter': sitter})

def search_sitters(request):
    query = request.GET.get('query', '')  
    sitters = Sitter.objects.filter(location__icontains=query)  
    return render(request, 'babysitter_app/search_results.html', {'sitters': sitters, 'query': query})

class ParentCreateView(CreateView):
    model = Parent
    form_class = ParentForm
    template_name = 'babysitter_app/create_parent.html'
    success_url = reverse_lazy('parent_list')

class ParentUpdateView(UpdateView):
    model = Parent
    form_class = ParentForm
    template_name = 'babysitter_app/create_parent.html'
    success_url = reverse_lazy('parent_list')

def parent_list(request):
    parents = Parent.objects.all().order_by('id')  
    paginator = Paginator(parents, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'babysitter_app/parent_list.html', {'page_obj': page_obj})  

class ParentDeleteView(DeleteView):
    model = Parent
    template_name = 'babysitter_app/delete_parent.html'
    success_url = reverse_lazy('parent_list')

class SitterList(APIView):
    def get(self, request):
        sitters = Sitter.objects.all()
        serializer = SitterSerializer(sitters, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = SitterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)