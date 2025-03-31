from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.core.validators import MinValueValidator
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.core.validators import MinValueValidator
from django.conf import settings
from django.utils.timezone import now 
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.conf import settings
from django.db import models

class CustomUser(AbstractUser):
    profile_picture = models.ImageField(upload_to="profile_pictures/", null=True, blank=True)
    
    USER_TYPES = (
        ('parent', 'Parent'),
        ('sitter', 'Sitter'),
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPES)

    groups = models.ManyToManyField(Group, related_name="custom_user_groups", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="custom_user_permissions", blank=True)

    def __str__(self):
        return self.username
class Sitter(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255)
    hourly_rate = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)
    experience = models.PositiveIntegerField(default=0)
    bio = models.TextField(default='')
    location = models.CharField(max_length=255, default='Unknown')
    rating = models.FloatField(default=0.0)
    favorite = models.BooleanField(default=False)
    accept_job = models.BooleanField(default=False)
    reply_message = models.TextField(null=True, blank=True)

    def save(self, *args, **kwargs):
        """ Only update user_type if it's a new instance, not every save """
        if self.user and not self.pk:
            self.user.user_type = 'sitter'
            self.user.save(update_fields=['user_type'])
        super().save(*args, **kwargs)  # ✅ Save sitter without affecting user

    def __str__(self):
        return self.name

class Parent(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    location = models.CharField(max_length=255, default="Unknown")
    email = models.EmailField(null=True, blank=True)
    number_of_children = models.PositiveIntegerField(default=1)
    booking_history = models.ManyToManyField('Job', through='ParentBookingHistory', related_name='parents')

    def save(self, *args, **kwargs):
        if self.user:
            self.user.user_type = 'parent'
            self.user.save()

            if not self.name:
                self.name = f"{self.user.first_name} {self.user.last_name}".strip() or self.user.username

        super().save(*args, **kwargs)

    def __str__(self):
        return self.name or "Unnamed Parent"

    
class Job(models.Model):
    sitter = models.ForeignKey('Sitter', on_delete=models.CASCADE, related_name="sitter_jobs")
    parent = models.ForeignKey('Parent', on_delete=models.CASCADE, related_name="parent_jobs", null=True, blank=True)
    job_date = models.DateTimeField()
    duration = models.PositiveIntegerField(validators=[MinValueValidator(1)])  # Duration in hours
    status = models.CharField(
        max_length=50, 
        choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('declined', 'Declined'), ('completed', 'Completed')], 
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)  # ✅ Correct way


    def __str__(self):
        parent_name = self.parent.name if self.parent else "Unknown Parent"
        sitter_name = self.sitter.name if self.sitter else "Unknown Sitter"
        return f'Job {self.id} - {parent_name} requested {sitter_name}'


class ParentBookingHistory(models.Model):
    parent = models.ForeignKey(Parent, on_delete=models.CASCADE, related_name="parent_bookings")
    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name="job_bookings")
    booking_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.parent.name} - {self.job} - {self.booking_date}"
    
class Review(models.Model):
    sitter = models.ForeignKey(Sitter, related_name='reviews', on_delete=models.CASCADE)
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    rating = models.PositiveIntegerField(choices=[(i, i) for i in range(1, 6)], default=1)
    comment = models.TextField(default='')

    def __str__(self):
        reviewer_name = self.reviewer.username if self.reviewer else "Anonymous"
        return f'Review for {self.sitter.name} by {reviewer_name}'
