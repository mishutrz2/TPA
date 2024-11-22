using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TPA.Domain.Models;
using TPA.Domain.Services.Interfaces;

namespace TPA.Domain.Services
{
    public class ListsService : IListsService
    {
        private readonly ApplicationDbContext _context;

        public ListsService(ApplicationDbContext context)
        {
            _context = context;
        }

        public IQueryable<List> GetLists()
        {
            return _context.Lists.AsQueryable();
        }

        public List? GetListById(Guid listId)
        {
            return _context.Lists.Where(l => l.ListId == listId).FirstOrDefault();
        }

        public void AddList(List list)
        {
            // TO DO validations and stuff
            _context.Lists.Add(list);
            _context.SaveChanges();
        }

        public void UpdateList(Guid listId, List updatedList)
        {
            var existingList = _context.Lists.Find(listId);
            if (existingList == null)
            {
                throw new Exception("List not found");
            }

            existingList.Name = updatedList.Name;
            existingList.Location = updatedList.Location;
            existingList.PasswordHash = updatedList.PasswordHash;

            _context.SaveChanges();
        }

        public void UpdateListPartial(Guid listId, Dictionary<string, object> updates)
        {
            var existingList = _context.Lists.Find(listId);
            if (existingList == null)
            {
                throw new Exception("List not found");
            }

            // Dynamically apply updates
            foreach (var update in updates)
            {
                var propertyInfo = typeof(List).GetProperty(update.Key);
                if (propertyInfo != null)
                {
                    propertyInfo.SetValue(existingList, update.Value);
                }
            }

            _context.SaveChanges();
        }
    }
}
