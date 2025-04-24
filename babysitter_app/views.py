from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, QueryDict
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.core.paginator import Paginator
from django.urls import reverse_lazy
from django.conf import settings
from django.views.generic.edit import CreateView, UpdateView, DeleteView, FormView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions, generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, permission_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Sitter, Parent, Job, CustomUser
from .forms import (UserRegistrationForm, LoginForm, SitterForm, ParentForm)
from .serializers import (SitterSerializer, UserSerializer, JobSerializer, UserProfileSerializer, SitterProfileSerializer, ParentProfileSerializer)
from .utils.mpesa import get_mpesa_access_token, generate_mpesa_password
import requests
import logging
import json

@csrf_exempt
def pay_with_mpesa(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=400)

    try:
        data = json.loads(request.body.decode("utf-8"))
        booking_id = data.get("booking_id")
        phone_number = "254718524806"
        amount = 1 

        if not booking_id:
            return JsonResponse({"error": "Booking ID is required"}, status=400)

        access_token = get_mpesa_access_token()
        if not access_token:
            return JsonResponse({"error": "Failed to get access token"}, status=500)

        password, timestamp = generate_mpesa_password()

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        payload = {
            "BusinessShortCode": settings.MPESA_SHORTCODE,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": amount,
            "PartyA": phone_number,
            "PartyB": settings.MPESA_SHORTCODE,
            "PhoneNumber": phone_number,
            "CallBackURL": settings.MPESA_CALLBACK_URL,
            "AccountReference": f"Booking{booking_id}",
            "TransactionDesc": "Payment for booking"
        }

        response = requests.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            headers=headers,
            json=payload
        )

        if response.status_code == 200:
            return JsonResponse(response.json(), status=200)
        else:
            return JsonResponse({"error": "Failed to initiate payment", "details": response.text}, status=400)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

class MpesaCallbackView(View):
    @csrf_exempt
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body.decode("utf-8"))
            print("M-Pesa Callback Data:", json.dumps(data, indent=2))            
            result_code = data.get("Body", {}).get("stkCallback", {}).get("ResultCode")
            
            if result_code == 0:
                print("✅ Payment successful")
                
                booking_id = data.get('Body', {}).get('stkCallback', {}).get('BookingId')  
                if booking_id:
                    Job.objects.filter(id=booking_id).update(status="paid")  
                    return JsonResponse({"status": "success", "message": "Payment successful!"}, status=200)
                else:
                    return JsonResponse({"status": "failed", "message": "Booking ID missing in the callback"}, status=400)
            else:
                print("❌ Payment failed")
                return JsonResponse({"status": "failed", "message": "Payment failed"}, status=200)

        except Exception as e:
            print("Callback error:", str(e))
            return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def mpesa_callback(request):
    if request.method == 'POST':
        try:
            payload = json.loads(request.body)

            result_code = payload.get("Body", {}).get("stkCallback", {}).get("ResultCode")
            metadata = payload.get("Body", {}).get("stkCallback", {}).get("CallbackMetadata", {})
            
            if result_code == 0:
                booking_id = metadata.get("Item", [{}])[0].get("Value")  
                
                job = Job.objects.get(id=booking_id) 
                job.payment_status = 'paid'
                job.save()

                parent = job.parent
                sitter = job.sitter

                print(f"✅ Payment for Job {job.id} successful. Notify parent: {parent.name}, sitter: {sitter.name}")

                return JsonResponse({'status': 'Payment recorded successfully'})
            else:
                return JsonResponse({'error': 'Payment failed'}, status=400)

        except Job.DoesNotExist:
            return JsonResponse({'error': 'Job not found'}, status=404)
        except Exception as e:
            print("Callback Error:", e)
            return JsonResponse({'error': 'Invalid callback'}, status=400)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)
def job_status_view(request, booking_id):
    job = get_object_or_404(Job, id=booking_id)

    return JsonResponse({
        "id": job.id,
        "status": job.status,
        "sitter_name": job.sitter.name,  
    })

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def mark_job_completed(request, id):
    try:
        job = Job.objects.get(id=id)
        if job.status != 'accepted':
            return Response(
                {'error': 'Only accepted jobs can be marked completed.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if job.sitter.user != request.user:
            return Response(
                {'error': 'You are not authorized to complete this job.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        job.status = 'completed'
        job.save()
        return Response(
            JobSerializer(job).data,
            status=status.HTTP_200_OK
        )
        
    except Job.DoesNotExist:
        return Response(
            {'error': 'Job not found'},
            status=status.HTTP_404_NOT_FOUND
        )

logger = logging.getLogger(__name__)
@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user

    if hasattr(user, "sitter"):
        sitter = user.sitter

    if request.method == "PATCH":
        print(f"🔥 Received Data: {request.data}")  

        serializer = SitterProfileSerializer(sitter, data=request.data.get("sitter", {}), partial=True)
        if serializer.is_valid():
            print(f"✅ Valid Data: {serializer.validated_data}")  
            serializer.save()
            sitter.refresh_from_db() 
            return Response(serializer.data, status=200)

        print(f"❌ Serializer Errors: {serializer.errors}")  
        return Response(serializer.errors, status=400)  
def update_profile(request):
    user = request.user

    print(f"🔹 User: {user.username}, Type: {user.user_type}")

    if hasattr(user, "sitter"):
        profile = user.sitter
        print("✅ Found Sitter Profile")
    elif hasattr(user, "parent"):
        profile = user.parent
        print("✅ Found Parent Profile")
    else:
        print("❌ Profile not found")
        return Response({"error": "Profile not found"}, status=400)

    print(f"🔥 Incoming Request Data: {request.data}")

    sitter_data = request.data.get("sitter", None)

    if not sitter_data:
        print("❌ No sitter data provided")
        return Response({"error": "No sitter data provided"}, status=400)

    print(f"✅ Extracted Sitter Data: {sitter_data}")

    updated_fields = []
    for key, value in sitter_data.items():
        if hasattr(profile, key):
            print(f"🔄 Updating {key} -> {value}")
            setattr(profile, key, value)
            updated_fields.append(key)
        else:
            print(f"⚠️ Ignoring unknown field: {key}")

    if updated_fields:
        profile.save()  
        profile.refresh_from_db()
        print(f"✅ Updated Profile: {vars(profile)}")
        return Response({"message": "Profile updated successfully", "updated_fields": updated_fields})
    else:
        print("⚠️ No fields updated")
        return Response({"message": "No changes made"}, status=200)

class UpdateSitterProfileView(generics.RetrieveUpdateAPIView):
    """
    Allows a logged-in sitter to update their profile details.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = SitterProfileSerializer

    def get_object(self):
        user = self.request.user
        if hasattr(user, "sitter"):
            user.sitter.refresh_from_db()  
            return user.sitter
        return Response({"error": "User is not a sitter"}, status=400)



class UpdateParentProfileView(generics.RetrieveUpdateAPIView):
    """
    Allows a logged-in parent to update their profile details.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = ParentProfileSerializer

    def get_object(self):
        user = self.request.user
        if hasattr(user, "parent"):
            return user.parent
        return Response({"error": "User is not a parent"}, status=400)

class UserProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_object(self):
        return self.request.user 

@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])

def user_profile(request):
    user = request.user

    if hasattr(user, "sitter"):
        sitter = user.sitter

    if request.method == "PATCH":
        print(f"🔥 Received Data: {request.data}")
    serializer = SitterProfileSerializer(sitter, data=request.data, partial=True)
    if serializer.is_valid():
        print(f"✅ Valid Data: {serializer.validated_data}") 
        serializer.save()
        sitter.refresh_from_db() 
        return Response(serializer.data, status=200)
    print(f"❌ Serializer Errors: {serializer.errors}") 
    return Response(serializer.errors, status=400)
   
class LoginAPIView(APIView):
    permission_classes = [AllowAny]  

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "username": user.username,                            
                "user_type": user.user_type,  
                "role": user.user_type if hasattr(user, 'user_type') else "user"
            })
        else:
            return Response({"error": "Invalid credentials"}, status=401)

@method_decorator(csrf_exempt, name='dispatch')  
class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError({"detail": "Username already exists."})

        form = UserRegistrationForm(data=request.data)
        if form.is_valid():
            user = form.save(commit=False)
            user.user_type = request.data.get('user_type', 'parent')
            user.save()

            if user.user_type == 'parent':
                Parent.objects.create(user=user, name=user.username)
            elif user.user_type == 'sitter':
                Sitter.objects.create(
                    user=user,
                    name=user.username,  
                    experience=request.data.get('experience', 0),  
                    location=request.data.get('location', 'Unknown'),  
                    bio=request.data.get('bio', ''),  
                )
            refresh = RefreshToken.for_user(user)

            return Response({
                "message": "Registration successful!",
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "username": user.username,
                "role": user.user_type
            }, status=status.HTTP_201_CREATED)

        return Response({"errors": form.errors}, status=status.HTTP_400_BAD_REQUEST)

def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')  
            else:
                form.add_error(None, "Invalid username or password.")
    else:
        form = LoginForm()

    return render(request, 'registration/login.html', {'form': form})

@login_required
def user_logout(request):
    logout(request)
    return redirect('home')

User = get_user_model()

class UserListView(ListAPIView):
    queryset = User.objects.all().only("id", "username", "email")  
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]  

def home(request):
    sitters = Sitter.objects.all()
    return render (request, 'babysitter_app/home.html', {'sitters': sitters})
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .models import Sitter, Job
from .serializers import JobSerializer

class RequestSitterView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, sitter_id):
        try:
            user = request.user

            if not hasattr(user, "parent"):
                return Response({"error": "Only parents can request a sitter"}, status=403)

            sitter = Sitter.objects.get(id=sitter_id)

            job_data = request.data.copy()
            job_data["parent"] = user.parent.id if hasattr(user, "parent") else None
            job_data["sitter"] = sitter.id

            serializer = JobSerializer(data=job_data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)

        except Sitter.DoesNotExist:
            return Response({"error": "Sitter not found"}, status=404)
        except Exception as e:
            return Response({"error": "Something went wrong"}, status=500)

class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        data = {
            "id": user.id,
            "username": user.username,
            "is_parent": hasattr(user, "parent"),
            "is_sitter": hasattr(user, "sitter"),
            "parent": {"id": user.parent.id} if hasattr(user, "parent") else None,  
            "sitter": {"id": user.sitter.id} if hasattr(user, "sitter") else None,
        }
        return Response(data)


class JobListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            if hasattr(request.user, "parent"):
                jobs = Job.objects.select_related("sitter", "parent").filter(parent=request.user.parent) 
            elif hasattr(request.user, "sitter"):
                jobs = Job.objects.select_related("parent", "sitter").filter(sitter=request.user.sitter) 
            else:
                return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

            serializer = JobSerializer(jobs, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SitterBookingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not hasattr(request.user, 'sitter'):
            return Response({"error": "Unauthorized – Only sitters can access this."}, status=status.HTTP_403_FORBIDDEN)

        jobs = Job.objects.filter(sitter=request.user.sitter)
        serializer = JobSerializer(jobs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class CreateSitterView(FormView):
    template_name = 'babysitter_app/create_update_sitter.html'
    form_class = SitterForm

    def form_valid(self, form):
        form.save()  
        return redirect('sitter_list')  

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
        form.save()  
        return redirect('sitter_list')  

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))

def sitter_list(request):
    sitters = Sitter.objects.all().order_by('name')  
    paginator = Paginator(sitters, 10)

    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'babysitter_app/sitter_list.html', {'page_obj': page_obj})

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
    
class SitterDetail(APIView):
    def get(self, request, pk):
        sitter = get_object_or_404(Sitter, pk=pk)
        return Response(SitterSerializer(sitter).data, status=status.HTTP_200_OK)

class UpdateBookingStatusView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, id):
        user = request.user 
        job = get_object_or_404(Job, id=id)  

        if not hasattr(user, 'sitter') or job.sitter.user != user:
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        if job.status != 'pending':
            return Response({"error": "Booking cannot be modified"}, status=status.HTTP_400_BAD_REQUEST)

        new_status = request.data.get('status')
        if new_status not in ["accepted", "declined"]:
            return Response({"error": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

        job.status = new_status
        job.save()

        return Response({"message": f"Booking {id} marked as {new_status}"}, status=status.HTTP_200_OK)


class ParentBookingsView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = JobSerializer

    def get_queryset(self):
        """Return bookings belonging to the logged-in parent."""
        user = self.request.user

        if not hasattr(user, "parent"): 
            return Job.objects.none()  

        return Job.objects.filter(parent=user.parent).order_by("-job_date")
    
class CancelBookingView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, id):
        user = request.user
        job = get_object_or_404(Job, id=id)

        if not hasattr(user, "parent") or job.parent.user != user:
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        if job.status not in ["pending", "accepted"]:
            return Response({"error": "Cannot cancel this booking"}, status=status.HTTP_400_BAD_REQUEST)

        job.delete()
        return Response({"message": "Booking canceled successfully"}, status=status.HTTP_200_OK)

class ProfilePictureUploadView(APIView):
    def patch(self, request, *args, **kwargs):
        user = request.user 

        if "profile_picture" not in request.FILES:
            return Response({"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = request.FILES["profile_picture"]

        user.profile_picture.save(uploaded_file.name, uploaded_file, save=True)

        if user.profile_picture:
            profile_picture_url = request.build_absolute_uri(user.profile_picture.url)
        else:
            profile_picture_url = None

        return Response({"profile_picture": profile_picture_url}, status=status.HTTP_200_OK)
class ProfileView(generics.RetrieveUpdateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer 

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        print(f"🔥 Received Data in ProfileView: {request.data}") 
        response = super().update(request, *args, **kwargs)
        print(f"✅ Updated Profile Data: {response.data}")  
        return response
