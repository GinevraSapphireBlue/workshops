class User < ActiveRecord::Base
  
  attr_accessible :role
  
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  has_many :reviews
  has_many :products
  validates_presence_of :firstname, :lastname
  
  after_initialize :set_default_role
  
  ROLES = %w[admin default]
  
  private
  def set_default_role
    self.role ||= "default"
  end
end
