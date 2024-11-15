﻿namespace RentAndSell.Car.API.Data.Entities.Abstract
{
	public abstract class BaseEntity
	{
        public int Id { get; set; }
        public bool IsActive { get; set; } = true;
        public DateTime Created { get; set; } = DateTime.Now;
        public DateTime? Updated { get; set; }
        public DateTime? Deleted { get; set; }

        public bool? IsDeleted { get; set; } = false;
    }
}